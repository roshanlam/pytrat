from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI
from pydantic import BaseModel, ConfigDict

from pytrat.core import (
    KeyProvider,
    StaticKeySet,
    TokenVerifier,
    VerifierSettings,
    WorkloadJwtAuthenticator,
    WorkloadKeys,
)
from pytrat.fastapi import PyTraT, Transaction

TRUST_DOMAIN = "payments.internal"
TRANSFER_FIELDS = ["source_account", "destination_account", "amount_minor", "currency"]


class Transfer(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    source_account: str
    destination_account: str
    amount_minor: int  # integer minor units: floats are never bindable
    currency: str


def create_app(tts_keys: KeyProvider, workload_keys: WorkloadKeys) -> FastAPI:
    verifier = TokenVerifier(
        VerifierSettings(trust_domain=TRUST_DOMAIN, algorithms=frozenset({"ES256"})),
        tts_keys,  # trusted keys come from configuration, never from the token
    )
    pytrat = PyTraT(
        service="ledger-service",
        verifier=verifier,
        # Who is calling is established separately: a Txn-Token is not authentication.
        authenticator=WorkloadJwtAuthenticator(workload_keys, audience="ledger-service"),
        protected_prefixes=("/internal",),  # a forgotten route under /internal fails closed
    )
    app = FastAPI(lifespan=pytrat.lifespan)
    pytrat.install(app)

    authorized = pytrat.require_transaction(
        scope="payments.transfer",
        bind_fields=TRANSFER_FIELDS,
        allowed_callers=["payment-service"],
    )

    @app.post("/internal/ledger/entries", status_code=201)
    async def record(
        transfer: Transfer, txn: Annotated[Transaction, Depends(authorized)]
    ) -> dict[str, object]:
        # Only reached when the body matches the token's tctx exactly.
        return {"recorded": transfer.model_dump(), "txn": txn.id, "principal": txn.subject}

    return app


def production_app(keys_dir: Path = Path("keys")) -> FastAPI:
    return create_app(
        StaticKeySet.from_jwks_file(keys_dir / "tts-2026-11.jwks.json"),
        WorkloadKeys(
            {"payment-service": StaticKeySet.from_jwks_file(keys_dir / "payment-service.jwks.json")}
        ),
    )
