from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

import httpx
from fastapi import Depends, FastAPI

from pytrat.core import TokenVerifier, WorkloadAuthenticator
from pytrat.fastapi import PyTraT, Transaction
from pytrat.policy import AgentRequirements


def create_app(verifier: TokenVerifier, authenticator: WorkloadAuthenticator) -> FastAPI:
    pytrat = PyTraT(
        service="reports-service",
        verifier=verifier,
        authenticator=authenticator,
        protected_prefixes=("/internal",),
    )
    downstream = httpx.AsyncClient()

    # --8<-- [start:lifespan]
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        async with pytrat.lifespan(app), downstream:  # PyTraT's startup checks, then yours
            yield

    app = FastAPI(lifespan=lifespan)
    pytrat.install(app)
    # --8<-- [end:lifespan]

    # --8<-- [start:agents]
    agent_mediated = pytrat.require_transaction(
        scope="reports.generate",
        agents=AgentRequirements(enabled=True, maximum_hops=3, minimum_assurance="medium"),
    )

    @app.post("/internal/reports")
    async def generate(txn: Annotated[Transaction, Depends(agent_mediated)]) -> dict[str, str]:
        return {"txn": txn.id}

    # --8<-- [end:agents]

    # --8<-- [start:exempt]
    @app.get("/internal/healthz")
    @pytrat.exempt
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    # --8<-- [end:exempt]

    return app
