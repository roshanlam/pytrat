"""Run the demo story in-process: real HTTP semantics over ASGI, no ports, no containers."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Mapping
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path

import httpx
from fastapi import FastAPI

from pytrat.cli._demo.lab import Lab, Urls
from pytrat.cli._demo.services import create_gateway, create_ledger, create_payment, create_tts
from pytrat.core import MemorySink

TRANSFER = {
    "source_account": "account-A",
    "destination_account": "account-B",
    "amount_minor": 10_000,  # $100.00
    "currency": "USD",
}


class HostRouter(httpx.AsyncBaseTransport):
    """Routes requests to in-process ASGI apps by host name. Unknown hosts are refused.

    Apps are looked up per request, so services can be registered after the router is handed to
    the clients that use it.
    """

    def __init__(self) -> None:
        self.apps: dict[str, FastAPI] = {}

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        app = self.apps.get(request.url.host)
        if app is None:
            raise httpx.ConnectError(f"unknown host {request.url.host}", request=request)
        transport = httpx.ASGITransport(app=app, client=("10.0.0.1", 443))
        return await transport.handle_async_request(request)


@dataclass
class Deployment:
    """The four services wired together, plus the audit trail each one produced."""

    lab: Lab
    router: HostRouter
    ledger: FastAPI
    audit: dict[str, MemorySink] = field(default_factory=dict)

    async def transfer(self, body: Mapping[str, object] | None = None) -> httpx.Response:
        """A logged-in user asks the gateway for a transfer."""
        token = self.lab.user_access_token()
        async with httpx.AsyncClient(transport=self.router) as user:
            return await user.post(
                f"{self.lab.urls.gateway}/transfers",
                json=dict(body or TRANSFER),
                headers={"Authorization": f"Bearer {token.reveal()}"},
            )

    @property
    def ledger_entries(self) -> list[dict[str, object]]:
        """Entries the ledger actually recorded."""
        entries: list[dict[str, object]] = self.ledger.state.entries
        return entries


@asynccontextmanager
async def deploy(directory: Path, *, compromised: bool) -> AsyncIterator[Deployment]:
    """Start all four services in-process with freshly generated keys."""
    lab = Lab.create(directory, Urls())
    audit = {name: MemorySink() for name in ("tts", "payment-service", "ledger-service")}
    router = HostRouter()
    apps = router.apps
    apps["tts.payments.internal"] = create_tts(lab, audit["tts"])
    apps["gateway.payments.internal"] = create_gateway(lab, router)
    apps["payment.payments.internal"] = create_payment(
        lab, compromised=compromised, transport=router, audit=audit["payment-service"]
    )
    ledger = create_ledger(lab, audit=audit["ledger-service"])
    apps["ledger.payments.internal"] = ledger
    async with AsyncExitStack() as stack:
        for app in apps.values():
            await stack.enter_async_context(app.router.lifespan_context(app))
        yield Deployment(lab=lab, router=router, ledger=ledger, audit=audit)


def render(event_json: str) -> str:
    """Pretty-print one audit event."""
    return json.dumps(json.loads(event_json), indent=2, sort_keys=True)
