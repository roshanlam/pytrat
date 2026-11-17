"""The FastAPI application of the reference TTS.

Routes:

* ``POST /token``: the Txn-Token Request (txn-tokens-11 §11), form-encoded.
* ``GET /.well-known/jwks.json``: the public signing keys (PyTraT profile P2).
* ``GET /healthz``: liveness.

Responses never include internal details. Every token-endpoint response carries
``Cache-Control: no-store`` and ``Pragma: no-cache`` (RFC 6749 §5.1).
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Final

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from pytrat.core.audit import AuditSink, LoggingSink
from pytrat.core.clock import Clock, SystemClock
from pytrat.core.constants import (
    TOKEN_TYPE_ACCESS_TOKEN,
    TOKEN_TYPE_JWT,
    TOKEN_TYPE_SELF_SIGNED,
    TOKEN_TYPE_UNSIGNED_JSON,
)
from pytrat.core.errors import ReasonCode
from pytrat.core.keys import StaticKeySet
from pytrat.core.replay import InMemoryReplayStore
from pytrat.server.agent_profile import AgentProfile
from pytrat.server.audit_store import InMemoryIssuanceLog, IssuanceLog, SqliteIssuanceLog
from pytrat.server.errors import OAuthError, OAuthErrorCode
from pytrat.server.ratelimit import TokenBucketRateLimiter
from pytrat.server.settings import TtsSettings, load_settings
from pytrat.server.signing import FileKeySigner
from pytrat.server.subjects import (
    JwtAccessTokenValidator,
    JwtIssuer,
    SelfSignedValidator,
    SubjectTokenValidator,
    UnsignedJsonValidator,
)
from pytrat.server.token_endpoint import TokenEndpoint, TtsComponents
from pytrat.server.workloads import (
    CompositeAuthenticator,
    Headers,
    PrivateKeyJwtAuthenticator,
    TrustedProxyMtlsAuthenticator,
    WorkloadAuthenticator,
    WorkloadRegistry,
)

__all__ = ["build_components", "create_app", "create_app_from_settings", "error_response"]

_logger = logging.getLogger(__name__)

_NO_STORE: Final = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def error_response(error: OAuthError) -> JSONResponse:
    """RFC 6749 §5.2 error body with no-store headers (and ``WWW-Authenticate`` on 401)."""
    headers = dict(_NO_STORE)
    if error.status == 401:
        # RFC 6749 §5.2: a 401 invalid_client response includes WWW-Authenticate.
        headers["WWW-Authenticate"] = 'private_key_jwt error="invalid_client"'
    return JSONResponse(
        {"error": error.error.value, "error_description": error.description},
        status_code=error.status,
        headers=headers,
    )


_SERVER_ERROR: Final = OAuthError(
    OAuthErrorCode.SERVER_ERROR, "internal error", ReasonCode.DEPENDENCY_UNAVAILABLE
)


async def _read_body(request: Request, limit: int) -> bytes:
    too_large = OAuthError(
        OAuthErrorCode.INVALID_REQUEST,
        "request body is too large",
        ReasonCode.TOKEN_MALFORMED,
        status=413,
    )
    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > limit):
        raise too_large
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > limit:
            raise too_large
    return bytes(body)


def _headers(request: Request) -> Headers:
    collected: dict[str, list[str]] = {}
    for raw_name, raw_value in request.headers.raw:
        collected.setdefault(raw_name.decode("latin-1").lower(), []).append(
            raw_value.decode("latin-1")
        )
    return {name: tuple(values) for name, values in collected.items()}


def create_app(components: TtsComponents) -> FastAPI:
    """Build the TTS application from fully constructed collaborators."""
    endpoint = TokenEndpoint(components)
    jwks = components.signer.jwks()

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        for callback in components.on_shutdown:
            await callback()

    app = FastAPI(
        title="PyTraT Transaction Token Service",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    @app.post("/token")
    async def token(request: Request) -> Response:
        peer = request.client.host if request.client is not None else None
        try:
            body = await _read_body(request, components.settings.max_request_bytes)
        except OAuthError as exc:
            await endpoint.record_rejection(exc)
            return error_response(exc)
        try:
            result = await endpoint.handle(
                body, request.headers.get("content-type"), _headers(request), peer
            )
        except OAuthError as exc:
            return error_response(exc)
        except Exception as exc:  # noqa: BLE001 - last line of defence; nothing internal leaks
            _logger.error("token endpoint internal error: %s", type(exc).__name__)  # noqa: TRY400
            return error_response(_SERVER_ERROR)
        return JSONResponse(result.to_dict(), headers=dict(_NO_STORE))

    @app.get("/.well-known/jwks.json")
    async def jwks_document() -> Response:
        return JSONResponse(jwks, headers={"Cache-Control": "public, max-age=300"})

    @app.get("/healthz")
    async def healthz() -> Response:
        return JSONResponse({"status": "ok"}, headers=dict(_NO_STORE))

    return app


def _authenticator(
    settings: TtsSettings, registry: WorkloadRegistry, clock: Clock
) -> WorkloadAuthenticator:
    authenticators: list[WorkloadAuthenticator] = []
    if settings.workload_auth.private_key_jwt:
        authenticators.append(
            PrivateKeyJwtAuthenticator(
                registry,
                token_endpoint=settings.token_endpoint,
                algorithms=frozenset(settings.algorithms),
                replay_store=InMemoryReplayStore(clock=clock),
                clock=clock,
                leeway_seconds=settings.leeway_seconds,
                max_lifetime_seconds=settings.workload_auth.max_assertion_lifetime_seconds,
            )
        )
    if settings.workload_auth.trusted_proxy is not None:
        authenticators.append(
            TrustedProxyMtlsAuthenticator(settings.workload_auth.trusted_proxy, registry)
        )
    return CompositeAuthenticator(authenticators)


def _subject_validators(
    settings: TtsSettings, registry: WorkloadRegistry, clock: Clock
) -> dict[str, SubjectTokenValidator]:
    config = settings.subject_tokens
    validators: dict[str, SubjectTokenValidator] = {}
    if config.jwt_access_token:
        access = JwtAccessTokenValidator(
            (
                JwtIssuer(
                    issuer=issuer.issuer,
                    keys=StaticKeySet.from_jwks_file(issuer.jwks_path),
                    audience=issuer.audience,
                    algorithms=frozenset(issuer.algorithms),
                )
                for issuer in config.jwt_access_token
            ),
            clock=clock,
            leeway_seconds=settings.leeway_seconds,
        )
        validators[TOKEN_TYPE_ACCESS_TOKEN] = access
        validators[TOKEN_TYPE_JWT] = access
    if config.self_signed.enabled:
        validators[TOKEN_TYPE_SELF_SIGNED] = SelfSignedValidator(
            registry,
            tts_identifiers=frozenset({settings.issuer, settings.token_endpoint}),
            algorithms=frozenset(settings.algorithms),
            clock=clock,
            leeway_seconds=settings.leeway_seconds,
            max_age_seconds=config.self_signed.max_age_seconds,
        )
    if config.unsigned_json.allowed_workloads:
        validators[TOKEN_TYPE_UNSIGNED_JSON] = UnsignedJsonValidator(
            frozenset(config.unsigned_json.allowed_workloads), clock=clock
        )
    return validators


def build_components(
    settings: TtsSettings,
    *,
    clock: Clock | None = None,
    sink: AuditSink | None = None,
    allow_insecure_key_permissions: bool = False,
) -> TtsComponents:
    """Construct every collaborator from settings. Fails at startup on any invalid input.

    Raises:
        ConfigurationError: If keys, JWKS documents or the agent registry are invalid.
    """
    clock = clock or SystemClock()
    registry = WorkloadRegistry.from_settings(settings)
    log: IssuanceLog
    on_shutdown: tuple[Callable[[], Awaitable[None]], ...] = ()
    if settings.audit_db_path is not None:
        sqlite_log = SqliteIssuanceLog(settings.audit_db_path)
        log, on_shutdown = sqlite_log, (sqlite_log.close,)
    else:
        _logger.warning("audit_db_path is not set; the issuance log is in memory only")
        log = InMemoryIssuanceLog()
    return TtsComponents(
        settings=settings,
        signer=FileKeySigner.from_settings(
            settings, allow_insecure_permissions=allow_insecure_key_permissions
        ),
        authenticator=_authenticator(settings, registry, clock),
        subject_validators=_subject_validators(settings, registry, clock),
        issuance_policy=settings.issuance_policy,
        log=log,
        sink=sink or LoggingSink(),
        clock=clock,
        rate_limiter=TokenBucketRateLimiter(
            settings.rate_limit.requests_per_second, settings.rate_limit.burst, clock
        ),
        agent_profile=AgentProfile.from_settings(settings.agents),
        on_shutdown=on_shutdown,
    )


def create_app_from_settings(path: str | Path) -> FastAPI:
    """Load a YAML configuration file and build the application.

    Raises:
        ConfigurationError: If the configuration or anything it references is invalid.
    """
    return create_app(build_components(load_settings(path)))
