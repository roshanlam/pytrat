from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI
from pydantic import BaseModel, ConfigDict

from pytrat.core import (
    InMemoryReplayStore,
    TokenVerifier,
    WorkloadAuthenticator,
)
from pytrat.fastapi import PyTraT, Transaction
from pytrat.policy import load_policy


class Transfer(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    source_account: str
    destination_account: str
    amount_minor: int
    currency: str


def create_app(
    verifier: TokenVerifier, authenticator: WorkloadAuthenticator, policy_file: Path
) -> FastAPI:
    policy = load_policy(
        policy_file,
        expected_trust_domain=verifier.settings.trust_domain,  # refuse a policy for another domain
        replay_store=InMemoryReplayStore(),  # needed by `single_use: true`; per process only
    )
    pytrat = PyTraT(
        service="ledger-service",
        verifier=verifier,
        authenticator=authenticator,
        policy=policy,
        protected_prefixes=("/internal",),
    )
    app = FastAPI(lifespan=pytrat.lifespan)
    pytrat.install(app)

    # No arguments: the YAML resource whose (method, path) equals this route template.
    @app.post("/internal/ledger/entries", status_code=201)
    async def record(
        transfer: Transfer, txn: Annotated[Transaction, Depends(pytrat.require_transaction())]
    ) -> dict[str, str]:
        return {"txn": txn.id}

    # policy_id: the YAML resource with that name.
    by_name = pytrat.require_transaction(policy_id="account-read")

    @app.get("/internal/accounts/{account_id}")
    async def account(
        account_id: str, txn: Annotated[Transaction, Depends(by_name)]
    ) -> dict[str, str]:
        return {"account": account_id, "txn": txn.id}

    @app.post("/internal/reports")
    async def report(
        txn: Annotated[Transaction, Depends(pytrat.require_transaction())],
    ) -> dict[str, str]:
        return {"txn": txn.id}

    # Deliberately unguarded under a protected prefix: say so explicitly, or startup fails.
    @app.get("/internal/healthz")
    @pytrat.exempt
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app
