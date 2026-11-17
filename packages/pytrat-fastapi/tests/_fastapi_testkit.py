"""Shared helpers for pytrat-fastapi tests: real tokens, real workload JWTs, in-process ASGI."""

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Annotated

import httpx
import pytest
from fastapi import Depends, FastAPI
from pydantic import BaseModel, ConfigDict

from pytrat.core import MemorySink, WorkloadJwtAuthenticator
from pytrat.core.crypto import sign_compact
from pytrat.core.testing import TestKey, TokenFactory, generate_test_key
from pytrat.fastapi import PyTraT, Transaction

LEDGER = "ledger-service"
BIND = ["source_account", "destination_account", "amount_minor", "currency"]
TCTX = {
    "source_account": "account-A",
    "destination_account": "account-B",
    "amount_minor": 10000,
    "currency": "USD",
}


class Transfer(BaseModel):
    """Lax on purpose (FastAPI's default): "10000" is coerced to 10000."""

    source_account: str
    destination_account: str
    amount_minor: int
    currency: str


class StrictTransfer(Transfer):
    model_config = ConfigDict(strict=True)


@dataclass
class Kit:
    factory: TokenFactory
    workload_key: TestKey
    sink: MemorySink = field(default_factory=MemorySink)

    def workload_jwt(
        self, sub: str = "payment-service", *, aud: str = LEDGER, key: TestKey | None = None
    ) -> str:
        signer = key or self.workload_key
        now = int(self.factory.clock.now())
        claims = {"sub": sub, "aud": aud, "iat": now, "exp": now + 60}
        return sign_compact(
            claims, signer.private_key, alg=signer.alg, kid=signer.kid, typ="wit+jwt"
        )

    def headers(
        self, token: str | None = None, *, caller: str | None = "payment-service", **claims: object
    ) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        raw = token if token is not None else self.factory.mint(**claims)
        if raw:
            pairs.append(("Txn-Token", raw))
        if caller is not None:
            pairs.append(("Workload-Identity", self.workload_jwt(caller)))
        return pairs

    def pytrat(self, **overrides: object) -> PyTraT:
        options: dict[str, object] = {
            "service": LEDGER,
            "verifier": self.factory.verifier(),
            "authenticator": WorkloadJwtAuthenticator(
                self.workload_key.key_set(), audience=LEDGER, clock=self.factory.clock
            ),
            "audit": self.sink,
            "protected_prefixes": ("/internal",),
            **overrides,
        }
        return PyTraT(**options)  # type: ignore[arg-type]


@pytest.fixture
def kit() -> Kit:
    return Kit(factory=TokenFactory.create(), workload_key=generate_test_key("ES256"))


@asynccontextmanager
async def serve(app: FastAPI, pytrat: PyTraT) -> AsyncIterator[httpx.AsyncClient]:
    """Start the app (running PyTraT's startup) and yield an in-process client."""
    async with (
        pytrat.lifespan(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://ledger.internal"
        ) as client,
    ):
        yield client


type Seen = dict[str, object]


def ledger_app(
    pytrat: PyTraT, *, model: type[Transfer] = Transfer, **requirement: object
) -> tuple[FastAPI, Seen]:
    """The demo's ledger: one bound transfer endpoint that records what the handler received."""
    app = FastAPI(lifespan=pytrat.lifespan)
    pytrat.install(app)
    seen: Seen = {}
    options: dict[str, object] = {
        "scope": "payments.transfer",
        "bind_fields": BIND,
        "allowed_callers": ["payment-service"],
        **requirement,
    }
    requirement_dep = pytrat.require_transaction(**options)  # type: ignore[arg-type]

    @app.post("/internal/transfer")
    async def transfer(
        body: model,  # type: ignore[valid-type]
        txn: Annotated[Transaction, Depends(requirement_dep)],
    ) -> dict[str, object]:
        seen["body"] = body.model_dump(mode="python")
        seen["txn"] = txn
        return {"status": "posted", "txn": txn.id}

    return app, seen


Mint = Callable[..., str]
