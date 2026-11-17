"""The demo story end to end on one service: legitimate, tampered, and attacked requests."""

from __future__ import annotations

import pytest

from _fastapi_testkit import TCTX, Kit, ledger_app, serve
from pytrat.core import EventType, ReasonCode
from pytrat.core.testing import generate_test_key

BODY = dict(TCTX)


async def test_legitimate_transfer_succeeds_and_handler_gets_the_transaction(kit: Kit) -> None:
    pytrat = kit.pytrat()
    app, seen = ledger_app(pytrat)
    async with serve(app, pytrat) as client:
        response = await client.post(
            "/internal/transfer", json=BODY, headers=kit.headers(txn="txn-legit")
        )
    assert response.status_code == 200
    assert response.json() == {"status": "posted", "txn": "txn-legit"}
    txn = seen["txn"]
    assert txn.caller.id == "payment-service"
    assert txn.binding.checked == (
        "source_account",
        "destination_account",
        "amount_minor",
        "currency",
    )
    [event] = kit.sink.events
    assert event.event_type is EventType.AUTHORIZATION_GRANTED


async def test_tampered_amount_is_rejected_with_context_mismatch_and_audited(kit: Kit) -> None:
    pytrat = kit.pytrat()
    app, seen = ledger_app(pytrat)
    async with serve(app, pytrat) as client:
        response = await client.post(
            "/internal/transfer",
            json={**BODY, "amount_minor": 900000},
            headers=kit.headers(txn="txn-tampered"),
        )
    assert response.status_code == 403
    assert response.headers["content-type"] == "application/problem+json"
    problem = response.json()
    assert problem["reason_code"] == "TRANSACTION_CONTEXT_MISMATCH"
    assert problem["transaction_id"] == "txn-tampered"
    assert "900000" not in response.text
    assert "body" not in seen
    [event] = kit.sink.events
    assert event.event_type is EventType.AUTHORIZATION_DENIED
    assert event.reason_code is ReasonCode.TRANSACTION_CONTEXT_MISMATCH
    assert event.transaction_id == "txn-tampered"


async def test_missing_token_is_401_with_txn_token_challenge(kit: Kit) -> None:
    pytrat = kit.pytrat()
    app, _ = ledger_app(pytrat)
    async with serve(app, pytrat) as client:
        response = await client.post("/internal/transfer", json=BODY, headers=kit.headers(""))
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Txn-Token"
    assert response.json()["reason_code"] == "TOKEN_MISSING"
    [event] = kit.sink.events
    assert event.event_type is EventType.TOKEN_REJECTED


async def test_two_txn_token_headers_are_rejected(kit: Kit) -> None:
    pytrat = kit.pytrat()
    app, seen = ledger_app(pytrat)
    headers = [("Txn-Token", kit.factory.mint()), *kit.headers()]
    async with serve(app, pytrat) as client:
        response = await client.post("/internal/transfer", json=BODY, headers=headers)
    assert response.status_code in {400, 401}
    assert response.json()["reason_code"] == "TOKEN_MALFORMED"
    assert not seen


async def test_wrong_caller_is_403(kit: Kit) -> None:
    pytrat = kit.pytrat()
    app, _ = ledger_app(pytrat)
    async with serve(app, pytrat) as client:
        response = await client.post(
            "/internal/transfer", json=BODY, headers=kit.headers(caller="reporting-service")
        )
    assert response.status_code == 403
    assert response.json()["reason_code"] == "CALLER_NOT_ALLOWED"


async def test_no_workload_credential_is_401(kit: Kit) -> None:
    pytrat = kit.pytrat()
    app, _ = ledger_app(pytrat)
    async with serve(app, pytrat) as client:
        response = await client.post(
            "/internal/transfer", json=BODY, headers=kit.headers(caller=None)
        )
    assert response.status_code == 401
    assert response.json()["reason_code"] == "WORKLOAD_UNAUTHENTICATED"


async def test_forged_workload_credential_is_401(kit: Kit) -> None:
    pytrat = kit.pytrat()
    app, _ = ledger_app(pytrat)
    forged = kit.workload_jwt(key=generate_test_key("ES256"))
    headers = [("Txn-Token", kit.factory.mint()), ("Workload-Identity", forged)]
    async with serve(app, pytrat) as client:
        response = await client.post("/internal/transfer", json=BODY, headers=headers)
    assert response.status_code == 401
    assert response.json()["reason_code"] == "WORKLOAD_UNAUTHENTICATED"


async def test_token_for_another_trust_domain_is_401(kit: Kit) -> None:
    pytrat = kit.pytrat()
    app, _ = ledger_app(pytrat)
    async with serve(app, pytrat) as client:
        response = await client.post(
            "/internal/transfer", json=BODY, headers=kit.headers(aud="evil.example")
        )
    assert response.status_code == 401
    assert response.json()["reason_code"] == "TRUST_DOMAIN_MISMATCH"


async def test_insufficient_scope_is_403(kit: Kit) -> None:
    pytrat = kit.pytrat()
    app, _ = ledger_app(pytrat)
    async with serve(app, pytrat) as client:
        response = await client.post(
            "/internal/transfer", json=BODY, headers=kit.headers(scope="payments.read")
        )
    assert response.status_code == 403
    assert response.json()["reason_code"] == "SCOPE_INSUFFICIENT"


async def test_single_use_rejects_replay(kit: Kit) -> None:
    from pytrat.core import InMemoryReplayStore

    pytrat = kit.pytrat(replay_store=InMemoryReplayStore(clock=kit.factory.clock))
    app, _ = ledger_app(pytrat, single_use=True)
    token = kit.factory.mint()
    async with serve(app, pytrat) as client:
        first = await client.post("/internal/transfer", json=BODY, headers=kit.headers(token))
        second = await client.post("/internal/transfer", json=BODY, headers=kit.headers(token))
    assert first.status_code == 200
    assert second.status_code == 403
    assert second.json()["reason_code"] == "REPLAY_DETECTED"


async def test_no_response_body_or_log_contains_a_token(
    kit: Kit, caplog: pytest.LogCaptureFixture
) -> None:
    pytrat = kit.pytrat(debug=True)
    app, _ = ledger_app(pytrat)
    token = kit.factory.mint()
    async with serve(app, pytrat) as client:
        responses = [
            await client.post("/internal/transfer", json=BODY, headers=kit.headers(token)),
            await client.post(
                "/internal/transfer",
                json={**BODY, "amount_minor": 1},
                headers=kit.headers(token),
            ),
            await client.post("/internal/transfer", json=BODY, headers=kit.headers(token + "x")),
        ]
    for response in responses:
        assert token not in response.text
        assert token[:40] not in response.text
    assert all(token[:40] not in record.getMessage() for record in caplog.records)
