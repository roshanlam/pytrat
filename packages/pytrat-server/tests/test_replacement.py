"""Replacement Txn-Tokens (txn-tokens-11 §13.15)."""

from __future__ import annotations

import pytest

from pytrat.core import EventType, ReasonCode
from pytrat.core.crypto import sign_compact

DETAILS = {"source_account": "A", "destination_account": "B", "amount_minor": 1, "currency": "USD"}


def last_denial(tts):
    return [e for e in tts.sink.events if e.event_type is EventType.REPLACEMENT_DENIED][-1]


async def original(tts, **form):
    form.setdefault("scope", "payments.transfer payments.read")
    form.setdefault("request_details", DETAILS)
    form.setdefault("request_context", {"req_ip": "10.0.0.1"})
    return await tts.issue(**form)


async def test_immutables_unchanged_txn_tokens_11_s13_15(tts):
    """txn-tokens-11 §13.15: MUST NOT modify txn, sub and aud; tctx/act/iss copied."""
    first = await original(tts)
    before = tts.verifier().verify(first).claims
    tts.clock.advance(5)
    response = await tts.post(
        tts.replacement_form(
            first,
            scope="payments.read",
            request_details={"amount_minor": 999},
            request_context={"req_ip": "6.6.6.6", "hop": "payment-service"},
        )
    )
    assert response.status_code == 200, response.text
    after = tts.verifier().verify(response.json()["access_token"]).claims
    assert (after.txn, after.sub, after.aud, after.iss) == (
        before.txn,
        before.sub,
        before.aud,
        before.iss,
    )
    assert after.tctx == before.tctx
    assert str(after.scope) == "payments.read"
    assert after.req_wl == "payment-service"
    assert after.iat == tts.now
    # rctx only gains members; existing ones are never overwritten.
    assert after.rctx["req_ip"] == "10.0.0.1"
    assert after.rctx["hop"] == "payment-service"
    # Default: lifetime capped at the original exp.
    assert after.exp == before.exp
    event = tts.sink.of_type(EventType.TOKEN_REPLACED)[0]
    assert event.detail["dropped_keys"] == "tctx.amount_minor,rctx.req_ip"
    chain = await tts.log.chain(before.txn)
    assert [r.event_type for r in chain] == ["token.issued", "token.replaced"]


async def test_cannot_widen_scope_txn_tokens_11_s13_15(tts):
    """txn-tokens-11 §13.15: MUST NOT expand the scope of permitted actions."""
    first = await original(tts, scope="payments.read")
    response = await tts.post(tts.replacement_form(first, scope="payments.read payments.transfer"))
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_scope"
    assert last_denial(tts).reason_code is ReasonCode.REPLACEMENT_WIDENS_AUTHORIZATION
    assert last_denial(tts).transaction_id == tts.verifier().verify(first).claims.txn


async def test_scope_outside_requester_policy_is_rejected(make_tts):
    def restrict(config):
        config["issuance_policy"]["workloads"]["payment-service"]["scopes"] = ["ledger.write"]

    tts = make_tts(restrict)
    first = await original(tts)
    response = await tts.post(tts.replacement_form(first, scope="payments.read"))
    assert response.json()["error"] == "invalid_scope"
    assert last_denial(tts).reason_code is ReasonCode.SCOPE_INSUFFICIENT


async def test_expired_input_is_rejected_txn_tokens_11_s13_15(tts):
    """txn-tokens-11 §13.15: MUST NOT replace an expired Txn-Token (no leeway)."""
    first = await original(tts)
    tts.clock.advance(60)  # exactly exp; within the verifier's 5 s leeway, still refused
    response = await tts.post(tts.replacement_form(first))
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"
    assert last_denial(tts).reason_code is ReasonCode.TOKEN_EXPIRED
    tts.clock.advance(30)
    response = await tts.post(tts.replacement_form(first))
    assert last_denial(tts).reason_code is ReasonCode.TOKEN_EXPIRED


async def test_forged_txn_token_is_rejected(tts):
    """A Txn-Token not signed by this TTS cannot be replaced."""
    forged_key = tts.keys["attacker"]
    forged = sign_compact(
        tts.verifier().verify(await original(tts)).claims.to_payload(),
        forged_key.private_key,
        alg="ES256",
        kid="tts-1",
        typ="txntoken+jwt",
    )
    response = await tts.post(tts.replacement_form(forged))
    assert response.json()["error"] == "invalid_grant"
    assert last_denial(tts).reason_code is ReasonCode.SIGNATURE_INVALID


async def test_requester_without_replace_permission_is_rejected(tts):
    first = await original(tts)
    response = await tts.post(tts.replacement_form(first, workload="api-gateway"))
    assert response.json()["error"] == "unauthorized_client"
    assert last_denial(tts).reason_code is ReasonCode.ISSUANCE_NOT_AUTHORIZED


async def test_audience_change_is_rejected_txn_tokens_11_s13_15(tts):
    """txn-tokens-11 §13.15: aud MUST NOT change."""
    first = await original(tts)
    response = await tts.post(tts.replacement_form(first, audience="other.internal"))
    assert response.json()["error"] == "invalid_target"


async def test_txn_token_is_not_a_workload_credential_txn_tokens_11_s13_12(tts):
    """txn-tokens-11 §13.12: a Txn-Token cannot authenticate the requester."""
    first = await original(tts)
    form = tts.replacement_form(first, client_assertion=first)
    response = await tts.post(form)
    assert response.status_code == 401


@pytest.fixture
def extending(make_tts):
    def extend(config):
        config["replacement"] = {"extend_lifetime": True, "max_replacements_per_txn": 2}

    return make_tts(extend)


async def test_replacement_count_limit_when_extending_txn_tokens_11_s13_15(extending):
    """txn-tokens-11 §13.15: SHOULD limit replacements if lifetime may be extended."""
    tts = extending
    token = await original(tts)
    txn = tts.verifier().verify(token).claims.txn
    for _ in range(2):
        tts.clock.advance(30)
        response = await tts.post(tts.replacement_form(token))
        assert response.status_code == 200, response.text
        token = response.json()["access_token"]
        claims = tts.verifier().verify(token).claims
        assert claims.exp == tts.now + 60
        assert claims.txn == txn
    tts.clock.advance(30)
    response = await tts.post(tts.replacement_form(token))
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"
    assert last_denial(tts).reason_code is ReasonCode.REPLACEMENT_LIMIT_EXCEEDED
    assert await tts.log.replacement_count(txn) == 2
    assert tts.sink.of_type(EventType.TOKEN_REPLACED)[-1].detail["lifetime"] == "extended"


async def test_chain_is_reconstructed_from_log_pytrat_p9(tts):
    """PyTraT profile P9 / txn-tokens-11 §13.15: the call chain is kept by the TTS."""
    first = await original(tts)
    response = await tts.post(tts.replacement_form(first, scope="payments.read"))
    second = response.json()["access_token"]
    response = await tts.post(
        tts.replacement_form(second, workload="billing-agent", scope="payments.read")
    )
    assert response.status_code == 200
    txn = tts.verifier().verify(first).claims.txn
    chain = await tts.log.chain(txn)
    import json

    workloads = [json.loads(r.record)["event"]["caller_workload"] for r in chain]
    assert workloads == ["api-gateway", "payment-service", "billing-agent"]


async def test_concurrent_replacements_cannot_exceed_the_limit(extending, monkeypatch):
    """Security review #5: five simultaneous replacements of one txn against a limit of two."""
    import asyncio

    tts = extending
    token = await original(tts)
    txn = tts.verifier().verify(token).claims.txn
    count = type(tts.log).replacement_count

    async def yielding_count(self, txn_id: str) -> int:
        # A real (SQLite/PostgreSQL) log awaits I/O here, letting other requests interleave.
        result = await count(self, txn_id)
        await asyncio.sleep(0)
        return result

    monkeypatch.setattr(type(tts.log), "replacement_count", yielding_count)
    tts.clock.advance(30)
    responses = await asyncio.gather(*(tts.post(tts.replacement_form(token)) for _ in range(5)))
    statuses = sorted(response.status_code for response in responses)
    assert statuses == [200, 200, 400, 400, 400]
    assert await tts.log.replacement_count(txn) == 2
