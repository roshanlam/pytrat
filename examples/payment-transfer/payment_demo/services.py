"""The four demo services.

    user ──► api-gateway ──► payment-service ──► ledger-service
                  │
                  └──► TTS (token exchange)

* **api-gateway** (trusted edge): validates the transfer, exchanges the user's access token for a
  Transaction Token whose ``tctx`` records the authorized transfer, and calls the payment service.
* **payment-service**: protected by PyTraT; forwards the transfer to the ledger, propagating the
  *unchanged* Txn-Token. With ``compromised=True`` it rewrites the amount first.
* **ledger-service**: protected by PyTraT; binds the request body to ``tctx`` and only records an
  entry the token authorized.

Each internal hop also authenticates the calling workload with a signed workload JWT, because a
Transaction Token is never an authentication credential (txn-tokens-11 §13.12).
"""

# No `from __future__ import annotations`: FastAPI must resolve the `Depends(...)` annotations,
# which reference closure locals, at route-registration time.

from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from typing import Annotated

import httpx
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from payment_demo.lab import ALG, SCOPE, TRANSFER_FIELDS, TRUST_DOMAIN, TTS_ISSUER, Lab
from pytrat.client import (
    AsyncTransactionClient,
    AsyncTransactionTokenClient,
    PrivateKeyJwtCredential,
    WorkloadJwtAuth,
)
from pytrat.core import (
    AuditSink,
    PyTraTError,
    TokenVerifier,
    VerifierSettings,
    WorkloadJwtAuthenticator,
)
from pytrat.fastapi import PyTraT, Transaction, exception_handler, initiate_transaction
from pytrat.server import build_components, create_app, parse_settings

COMPROMISED_AMOUNT_MINOR = 900_000  # $9,000.00


class Transfer(BaseModel):
    """A transfer request. Strict: "10000" is not an integer, and floats are refused."""

    model_config = ConfigDict(strict=True, extra="forbid")

    source_account: str = Field(min_length=1, max_length=64)
    destination_account: str = Field(min_length=1, max_length=64)
    amount_minor: int = Field(gt=0, le=10_000_000)
    currency: str = Field(pattern=r"^[A-Z]{3}$")


def _verifier(lab: Lab) -> TokenVerifier:
    settings = VerifierSettings(
        trust_domain=TRUST_DOMAIN, algorithms=frozenset({ALG}), expected_issuer=TTS_ISSUER
    )
    return TokenVerifier(settings, lab.tts_keys())


def _http(transport: httpx.AsyncBaseTransport | None) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=transport, follow_redirects=False, timeout=5.0)


def _forward(response: httpx.Response) -> JSONResponse:
    """Relay a downstream response (problem documents included) to our caller."""
    return JSONResponse(
        response.json(),
        status_code=response.status_code,
        media_type=response.headers.get("content-type", "application/json"),
    )


def create_tts(lab: Lab, audit: AuditSink | None = None) -> FastAPI:
    """The reference Transaction Token Service."""
    settings = parse_settings(lab.tts_settings(), base_dir=lab.directory)
    return create_app(build_components(settings, sink=audit))


def create_gateway(lab: Lab, transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    """The trusted edge that initiates transactions."""
    urls = lab.urls
    tts = AsyncTransactionTokenClient(
        urls.token_endpoint,
        PrivateKeyJwtCredential(
            "api-gateway",
            lab.pem("api-gateway"),
            alg=ALG,
            kid="api-gateway",
            token_endpoint=urls.token_endpoint,
        ),
        _verifier(lab),
        http_client=_http(transport),
        allow_insecure_localhost=urls.insecure_localhost,
    )
    payments = AsyncTransactionClient(
        [urls.payment],
        http_client=_http(transport),
        auth=WorkloadJwtAuth(
            workload_id="api-gateway",
            private_key_path=lab.pem("api-gateway"),
            kid="api-gateway",
            alg=ALG,
            audiences={urls.payment: "payment-service"},
            allow_insecure_localhost=urls.insecure_localhost,
        ),
        allow_insecure_localhost=urls.insecure_localhost,
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        async with tts, payments:
            yield

    app = FastAPI(title="api-gateway", lifespan=lifespan)
    app.add_exception_handler(PyTraTError, exception_handler())

    @app.post("/transfers")
    async def create_transfer(transfer: Transfer, request: Request) -> JSONResponse:
        # A real gateway also authenticates the user here; the TTS independently validates the
        # access token before issuing (txn-tokens-11 §11.3).
        async with initiate_transaction(
            request,
            client=tts,
            audience=TRUST_DOMAIN,
            scope=SCOPE,
            request_details=transfer.model_dump(),
            request_context={"channel": "web"},
        ) as txn:
            response = await payments.post(
                f"{urls.payment}/internal/payments", json=transfer.model_dump()
            )
        body = response.json()
        if response.is_success:
            body["transaction_id"] = txn.id
        return JSONResponse(body, status_code=response.status_code)

    return app


def create_payment(
    lab: Lab,
    *,
    compromised: bool = False,
    transport: httpx.AsyncBaseTransport | None = None,
    audit: AuditSink | None = None,
) -> FastAPI:
    """The payment service. ``compromised=True`` simulates an attacker controlling it."""
    urls = lab.urls
    pytrat = PyTraT(
        service="payment-service",
        verifier=_verifier(lab),
        authenticator=WorkloadJwtAuthenticator(lab.workload_keys(), audience="payment-service"),
        audit=audit,
        protected_prefixes=("/internal",),
    )
    ledger = AsyncTransactionClient(
        [urls.ledger],
        http_client=_http(transport),
        auth=WorkloadJwtAuth(
            workload_id="payment-service",
            private_key_path=lab.pem("payment-service"),
            kid="payment-service",
            alg=ALG,
            audiences={urls.ledger: "ledger-service"},
            allow_insecure_localhost=urls.insecure_localhost,
        ),
        allow_insecure_localhost=urls.insecure_localhost,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        async with pytrat.lifespan(app), ledger:
            yield

    app = FastAPI(title="payment-service", lifespan=lifespan)
    pytrat.install(app)
    authorized = pytrat.require_transaction(
        scope=SCOPE, bind_fields=list(TRANSFER_FIELDS), allowed_callers=["api-gateway"]
    )

    @app.post("/internal/payments")
    async def pay(
        transfer: Transfer, txn: Annotated[Transaction, Depends(authorized)]
    ) -> JSONResponse:
        entry: Mapping[str, object] = transfer.model_dump()
        if compromised:
            # The attacker controls this process: it can change anything it sends, but it holds
            # no signing key, so it cannot change what the Txn-Token authorized.
            entry = {**entry, "amount_minor": COMPROMISED_AMOUNT_MINOR}
        # The bound Txn-Token is forwarded unchanged (txn-tokens-11 §12.2).
        return _forward(await ledger.post(f"{urls.ledger}/internal/ledger/entries", json=entry))

    return app


def create_ledger(lab: Lab, *, audit: AuditSink | None = None) -> FastAPI:
    """The ledger: the last line of defence for the authorized amount."""
    pytrat = PyTraT(
        service="ledger-service",
        verifier=_verifier(lab),
        authenticator=WorkloadJwtAuthenticator(lab.workload_keys(), audience="ledger-service"),
        audit=audit,
        protected_prefixes=("/internal",),
    )
    app = FastAPI(title="ledger-service", lifespan=pytrat.lifespan)
    pytrat.install(app)
    entries: list[dict[str, object]] = []
    app.state.entries = entries
    authorized = pytrat.require_transaction(
        scope=SCOPE, bind_fields=list(TRANSFER_FIELDS), allowed_callers=["payment-service"]
    )

    @app.post("/internal/ledger/entries", status_code=201)
    async def record(
        transfer: Transfer, txn: Annotated[Transaction, Depends(authorized)]
    ) -> dict[str, object]:
        entry = {**transfer.model_dump(), "transaction_id": txn.id, "principal": txn.subject}
        entries.append(entry)
        return {"status": "recorded", "entry": entry}

    return app
