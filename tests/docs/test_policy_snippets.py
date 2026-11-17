"""The policy guide's YAML and FastAPI wiring behave as documented."""

# No `from __future__ import annotations`: FastAPI must resolve Depends() on local objects.

import time
from pathlib import Path
from typing import Annotated

import httpx
import pytest
from fastapi import Depends, FastAPI

from pytrat.client import WorkloadJwtAuth
from pytrat.core import (
    TXN_TOKEN_HEADER,
    ConfigurationError,
    FrozenClock,
    InMemoryReplayStore,
    WorkloadJwtAuthenticator,
    WorkloadKeys,
)
from pytrat.core.crypto import private_key_to_pem
from pytrat.core.testing import TokenFactory, generate_test_key
from pytrat.fastapi import PyTraT, Transaction
from pytrat.policy import load_policy

from .conftest import SNIPPETS

POLICY = SNIPPETS / "policy.yaml"
BASE = "https://ledger.internal"
TRANSFER = {
    "source_account": "account-A",
    "destination_account": "account-B",
    "amount_minor": 10000,
    "currency": "USD",
}


def test_policy_yaml_compiles() -> None:
    policy_set = load_policy(
        POLICY, expected_trust_domain="payments.internal", replay_store=InMemoryReplayStore()
    )
    assert [policy.policy_id for _, policy in policy_set.routes] == [
        "ledger-entry",
        "account-read",
        "report-generate",
        "metrics",
    ]


@pytest.fixture
def world(tmp_path: Path):
    tts = TokenFactory.create("ES256", clock=FrozenClock(time.time()))
    caller = generate_test_key("ES256", kid="payment-service")
    pem = tmp_path / "caller.pem"
    pem.write_bytes(private_key_to_pem(caller.private_key))
    authenticator = WorkloadJwtAuthenticator(
        WorkloadKeys({"payment-service": caller.key_set()}), audience="ledger-service"
    )
    auth = WorkloadJwtAuth(
        workload_id="payment-service",
        private_key_path=pem,
        kid="payment-service",
        alg="ES256",
        audiences={BASE: "ledger-service"},
    )
    return tts, authenticator, auth


async def test_policy_app_enforces_the_yaml(snippet, world) -> None:
    tts, authenticator, auth = world
    app = snippet("policy_app").create_app(tts.verifier(), authenticator, POLICY)
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url=BASE, auth=auth) as client,
    ):
        token = {TXN_TOKEN_HEADER: tts.mint()}
        url = "/internal/ledger/entries"
        assert (await client.post(url, json=TRANSFER, headers=token)).status_code == 201
        replay = await client.post(url, json=TRANSFER, headers=token)
        assert replay.json()["reason_code"] == "REPLAY_DETECTED"

        assert (await client.get("/internal/accounts/account-A", headers=token)).status_code == 200
        other = await client.get("/internal/accounts/account-Z", headers=token)
        assert other.json()["reason_code"] == "TRANSACTION_CONTEXT_MISMATCH"

        reports = {TXN_TOKEN_HEADER: tts.mint(scope="reports.generate")}
        no_agents = await client.post("/internal/reports", headers=reports)
        assert no_agents.json()["reason_code"] == "AGENT_CONTEXT_MISSING"

        assert (await client.get("/internal/healthz")).status_code == 200


async def test_fastapi_refuses_transactionless_resources_at_startup(world) -> None:
    tts, authenticator, _ = world
    pytrat = PyTraT(
        service="ledger-service",
        verifier=tts.verifier(),
        authenticator=authenticator,
        policy=load_policy(POLICY, replay_store=InMemoryReplayStore()),
    )
    app = FastAPI()

    @app.get("/internal/metrics")
    async def metrics(_: Annotated[Transaction, Depends(pytrat.require_transaction())]) -> None:
        return None

    with pytest.raises(ConfigurationError):
        pytrat.prepare(app)


async def test_fastapi_extras_snippet(snippet, world) -> None:
    tts, authenticator, auth = world
    app = snippet("fastapi_extras").create_app(tts.verifier(), authenticator)
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url=BASE, auth=auth) as client,
    ):
        assert (await client.get("/internal/healthz")).status_code == 200
        plain = {TXN_TOKEN_HEADER: tts.mint(scope="reports.generate")}
        denied = await client.post("/internal/reports", headers=plain)
        assert denied.json()["reason_code"] == "AGENT_CONTEXT_MISSING"
        chain = {
            "originator": {"id": "research-agent"},
            "proximate_agent": {"id": "research-agent"},
            "chain_metadata": {"hop_count": 1, "min_assurance_level": "high"},
        }
        agent = {TXN_TOKEN_HEADER: tts.mint(scope="reports.generate", agentic_ctx=chain)}
        assert (await client.post("/internal/reports", headers=agent)).status_code == 200
