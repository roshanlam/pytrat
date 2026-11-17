"""In-process end-to-end benchmarks (no network sockets).

Run with:  uv run pytest benchmarks --benchmark-only

* A full FastAPI request through ``require_transaction`` (Txn-Token verification, workload-JWT
  authentication, four-field ``tctx`` binding, audit to ``NullSink``) over ``httpx.ASGITransport``,
  next to the same route without PyTraT, so the difference is PyTraT's per-request cost.
* A token exchange against the reference TTS, also over ``httpx.ASGITransport``: the client signs
  an RFC 7523 assertion, the TTS authenticates it, validates the subject access token, applies the
  issuance policy, signs and records the token, and the client verifies the result.

Log records below WARNING are disabled while measuring: handler cost depends on the deployment.
"""

# No `from __future__ import annotations`: FastAPI must resolve Depends() on local objects.

import asyncio
import json
import logging
import os
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Annotated

import httpx
import pytest
from fastapi import Depends, FastAPI
from pydantic import BaseModel, ConfigDict

from pytrat.client import AsyncTransactionTokenClient, PrivateKeyJwtCredential
from pytrat.core import (
    TXN_TOKEN_HEADER,
    FrozenClock,
    NullSink,
    SecretToken,
    TokenVerifier,
    VerifierSettings,
    WorkloadJwtAuthenticator,
    WorkloadKeys,
)
from pytrat.core.constants import TOKEN_TYPE_ACCESS_TOKEN
from pytrat.core.crypto import private_key_to_pem, sign_compact
from pytrat.core.testing import TokenFactory, generate_test_key
from pytrat.fastapi import PyTraT, Transaction
from pytrat.server import build_components, create_app, parse_settings

FIELDS = ["source_account", "destination_account", "amount_minor", "currency"]
TRANSFER = {
    "source_account": "account-A",
    "destination_account": "account-B",
    "amount_minor": 10000,
    "currency": "USD",
}
LEDGER = "https://ledger.internal"
TTS = "https://tts.payments.internal"


class Transfer(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    source_account: str
    destination_account: str
    amount_minor: int
    currency: str


@pytest.fixture(autouse=True)
def _quiet_logging() -> Iterator[None]:
    logging.disable(logging.INFO)
    yield
    logging.disable(logging.NOTSET)


@pytest.fixture
def run() -> Iterator[Callable[..., object]]:
    loop = asyncio.new_event_loop()
    yield loop.run_until_complete
    loop.close()


def _ledger(pytrat: PyTraT | None) -> FastAPI:
    if pytrat is None:
        app = FastAPI()

        @app.post("/internal/ledger/entries", status_code=201)
        async def plain(transfer: Transfer) -> dict[str, str]:
            return {"status": "recorded"}

        return app

    app = FastAPI(lifespan=pytrat.lifespan)
    pytrat.install(app)
    authorized = pytrat.require_transaction(
        scope="payments.transfer", bind_fields=FIELDS, allowed_callers=["payment-service"]
    )

    @app.post("/internal/ledger/entries", status_code=201)
    async def record(
        transfer: Transfer, txn: Annotated[Transaction, Depends(authorized)]
    ) -> dict[str, str]:
        return {"status": "recorded"}

    return app


def _workload_jwt(key, audience: str) -> str:
    now = int(time.time())
    claims = {"sub": "payment-service", "aud": audience, "iat": now, "exp": now + 300}
    return sign_compact(claims, key.private_key, alg="ES256", kid=key.kid, typ="wit+jwt")


@pytest.mark.parametrize("protected", [False, True], ids=["fastapi-baseline", "fastapi-pytrat"])
def test_fastapi_request(benchmark, run, protected: bool) -> None:
    tts = TokenFactory.create("ES256", clock=FrozenClock(time.time()), lifetime=300)
    caller = generate_test_key("ES256", kid="payment-service")
    pytrat = None
    headers: dict[str, str] = {}
    if protected:
        pytrat = PyTraT(
            service="ledger-service",
            verifier=TokenVerifier(
                VerifierSettings(trust_domain="payments.internal", algorithms=frozenset({"ES256"})),
                tts.key.key_set(),
            ),
            authenticator=WorkloadJwtAuthenticator(
                WorkloadKeys({"payment-service": caller.key_set()}), audience="ledger-service"
            ),
            audit=NullSink(),
            protected_prefixes=("/internal",),
        )
        headers = {
            TXN_TOKEN_HEADER: tts.mint(),
            "Workload-Identity": _workload_jwt(caller, "ledger-service"),
        }
    app = _ledger(pytrat)
    body = json.dumps(TRANSFER).encode()
    headers["Content-Type"] = "application/json"

    async def setup() -> tuple[httpx.AsyncClient, object]:
        lifespan = app.router.lifespan_context(app)
        await lifespan.__aenter__()
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=LEDGER)
        return client, lifespan

    client, lifespan = run(setup())

    def request() -> httpx.Response:
        return run(client.post("/internal/ledger/entries", content=body, headers=headers))

    response = benchmark(request)
    assert response.status_code == 201, response.text
    run(client.aclose())
    run(lifespan.__aexit__(None, None, None))


def _secret(path: Path, data: bytes) -> Path:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
    return path


def test_tts_issuance(benchmark, run, tmp_path: Path) -> None:
    tts_key, idp = generate_test_key("ES256", kid="tts-1"), generate_test_key("ES256", kid="idp")
    gateway = generate_test_key("ES256", kid="api-gateway")
    _secret(tmp_path / "tts.pem", private_key_to_pem(tts_key.private_key))
    gateway_pem = _secret(tmp_path / "gw.pem", private_key_to_pem(gateway.private_key))
    (tmp_path / "idp.json").write_text(json.dumps({"keys": [idp.jwk()]}))
    settings = parse_settings(
        {
            "trust_domain": "payments.internal",
            "issuer": TTS,
            "token_endpoint": f"{TTS}/token",
            "signing_keys": [{"kid": "tts-1", "alg": "ES256", "private_key_path": "tts.pem"}],
            "workloads": [{"id": "api-gateway", "jwks": {"keys": [gateway.jwk()]}}],
            "subject_tokens": {
                "jwt_access_token": [
                    {"issuer": "https://idp.example", "jwks_path": "idp.json", "audience": "api"}
                ]
            },
            "issuance_policy": {
                "workloads": {
                    "api-gateway": {
                        "scopes": ["payments.transfer"],
                        "tctx": {
                            "source_account": "string",
                            "destination_account": "string",
                            "amount_minor": "integer",
                            "currency": "string",
                        },
                    }
                }
            },
            # Measure issuance, not the per-workload rate limiter.
            "rate_limit": {"requests_per_second": 1_000_000.0, "burst": 1_000_000},
        },
        base_dir=tmp_path,
    )
    app = create_app(build_components(settings, sink=NullSink()))
    http = httpx.AsyncClient(transport=httpx.ASGITransport(app=app))
    verifier = TokenVerifier(
        VerifierSettings(
            trust_domain="payments.internal", algorithms=frozenset({"ES256"}), expected_issuer=TTS
        ),
        tts_key.key_set(),
    )
    client = AsyncTransactionTokenClient(
        f"{TTS}/token",
        PrivateKeyJwtCredential(
            "api-gateway",
            gateway_pem,
            alg="ES256",
            kid="api-gateway",
            token_endpoint=f"{TTS}/token",
        ),
        verifier,
        http_client=http,
    )
    now = int(time.time())
    access_token = SecretToken(
        sign_compact(
            {
                "iss": "https://idp.example",
                "aud": "api",
                "sub": "user:123",
                "scope": "payments.transfer",
                "iat": now,
                "exp": now + 3600,
                "client_id": "web-app",
            },
            idp.private_key,
            alg="ES256",
            kid="idp",
            typ="at+jwt",
        )
    )

    def issue() -> object:
        return run(
            client.issue(
                audience="payments.internal",
                scope="payments.transfer",
                subject_token=access_token,
                subject_token_type=TOKEN_TYPE_ACCESS_TOKEN,
                request_details=TRANSFER,
            )
        )

    token = benchmark(issue)
    assert token.claims.tctx == TRANSFER  # type: ignore[attr-defined]
    run(http.aclose())
