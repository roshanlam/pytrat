"""The payment-transfer security story, end to end.

Gateway → TTS → payment-service → ledger-service, all real PyTraT components in-process. These
tests run the shipped example code, so the demo cannot silently stop demonstrating the point.
"""

from __future__ import annotations

import sys
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from pytrat.core import EventType, ReasonCode

sys.path.insert(0, str(Path(__file__).parents[2] / "examples" / "payment-transfer"))

from pytrat.cli._demo.scenario import TRANSFER, Deployment, deploy

pytestmark = pytest.mark.integration


@pytest.fixture
async def honest(tmp_path: Path) -> AsyncIterator[Deployment]:
    async with deploy(tmp_path, compromised=False) as deployment:
        yield deployment


@pytest.fixture
async def compromised(tmp_path: Path) -> AsyncIterator[Deployment]:
    async with deploy(tmp_path, compromised=True) as deployment:
        yield deployment


async def test_legitimate_transfer_is_recorded(honest: Deployment) -> None:
    response = await honest.transfer()
    assert response.status_code == 201
    [entry] = honest.ledger_entries
    assert entry["amount_minor"] == 10_000
    assert entry["principal"] == "user:123"
    assert entry["transaction_id"] == response.json()["transaction_id"]
    granted = honest.audit["ledger-service"].of_type(EventType.AUTHORIZATION_GRANTED)
    assert granted[0].caller_workload == "payment-service"
    assert granted[0].transaction_id == entry["transaction_id"]


async def test_one_transaction_spans_every_hop(honest: Deployment) -> None:
    await honest.transfer()
    issued = honest.audit["tts"].of_type(EventType.TOKEN_ISSUED)[0].transaction_id
    payment = honest.audit["payment-service"].of_type(EventType.AUTHORIZATION_GRANTED)[0]
    ledger = honest.audit["ledger-service"].of_type(EventType.AUTHORIZATION_GRANTED)[0]
    assert issued == payment.transaction_id == ledger.transaction_id
    # Forwarded unchanged (txn-tokens-11 §12.2): both services saw the very same token.
    assert payment.token_digest == ledger.token_digest


async def test_compromised_intermediary_cannot_change_the_amount(compromised: Deployment) -> None:
    response = await compromised.transfer()
    assert response.status_code == 403
    assert response.json()["reason_code"] == "TRANSACTION_CONTEXT_MISMATCH"
    assert compromised.ledger_entries == []
    [denial] = compromised.audit["ledger-service"].of_type(EventType.AUTHORIZATION_DENIED)
    assert denial.reason_code is ReasonCode.TRANSACTION_CONTEXT_MISMATCH
    assert denial.caller_workload == "payment-service"
    assert "amount_minor" in denial.detail["check"]
    rendered = denial.to_json()
    assert "900000" not in rendered
    assert "10000" not in rendered


async def test_user_cannot_request_more_than_validated_body(honest: Deployment) -> None:
    """The gateway validates strictly: a float amount never reaches the TTS."""
    response = await honest.transfer({**TRANSFER, "amount_minor": 100.0})
    assert response.status_code == 422
    assert honest.audit["tts"].events == []


async def _direct(deployment: Deployment, url: str, headers: dict[str, str]) -> httpx.Response:
    async with httpx.AsyncClient(transport=deployment.router) as client:
        return await client.post(url, json=TRANSFER, headers=headers)


async def test_ledger_rejects_calls_without_a_transaction(honest: Deployment) -> None:
    response = await _direct(honest, f"{honest.lab.urls.ledger}/internal/ledger/entries", {})
    assert response.status_code == 401
    assert response.json()["reason_code"] == "TOKEN_MISSING"


async def test_access_token_is_not_accepted_as_a_transaction_token(honest: Deployment) -> None:
    """A user access token is a different credential type (txn-tokens-11 §9.1 typ)."""
    token = honest.lab.user_access_token().reveal()
    response = await _direct(
        honest, f"{honest.lab.urls.ledger}/internal/ledger/entries", {"Txn-Token": token}
    )
    assert response.status_code == 401
    assert response.json()["reason_code"] == "TOKEN_TYPE_INVALID"


async def test_token_never_leaves_the_trust_domain_in_responses(honest: Deployment) -> None:
    response = await honest.transfer()
    assert "eyJ" not in response.text
