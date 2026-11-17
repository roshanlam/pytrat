"""Issuance through the HTTP token endpoint (txn-tokens-11 §11)."""

from __future__ import annotations

from urllib.parse import urlencode

import pytest

from pytrat.core import EventType, ReasonCode
from pytrat.core.constants import (
    TOKEN_TYPE_REFRESH_TOKEN,
    TOKEN_TYPE_SELF_SIGNED,
    TOKEN_TYPE_TXN_TOKEN,
    TOKEN_TYPE_UNSIGNED_JSON,
)
from pytrat.core.crypto import peek_header

TRUST_DOMAIN = "payments.internal"


def last_denial(tts):
    denials = [e for e in tts.sink.events if e.event_type is EventType.ISSUANCE_DENIED]
    assert denials, "no denial was audited"
    return denials[-1]


async def test_conforming_response_txn_tokens_11_s11_4(tts):
    """txn-tokens-11 §11.4: N_A token_type, txn_token issued type, no refresh_token, no-store."""
    response = await tts.post(tts.form())
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"access_token", "issued_token_type", "token_type", "expires_in"}
    assert body["token_type"] == "N_A"
    assert body["issued_token_type"] == TOKEN_TYPE_TXN_TOKEN
    assert body["expires_in"] == 60
    assert "refresh_token" not in body
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    assert response.headers["content-type"] == "application/json"


async def test_issued_token_verifies_with_published_jwks_txn_tokens_11_s9(tts):
    """txn-tokens-11 §9.1, §9.2, §11.3: header typ/kid and required claims."""
    jwks = (await tts.get("/.well-known/jwks.json")).json()
    assert {key["kid"] for key in jwks["keys"]} == {"tts-1", "tts-0"}
    assert all("d" not in key for key in jwks["keys"])
    token = await tts.issue(
        request_details={
            "source_account": "A",
            "destination_account": "B",
            "amount_minor": 10000,
            "currency": "USD",
        },
        request_context={"req_ip": "10.0.0.1"},
    )
    header = peek_header(token, max_bytes=16384)
    assert header.kid == "tts-1"
    claims = tts.verifier(jwks).verify(token).claims
    assert claims.aud == TRUST_DOMAIN
    assert claims.iss == "https://tts.payments.internal"
    assert claims.sub == "user:alice"
    assert str(claims.scope) == "payments.transfer"
    assert claims.req_wl == "api-gateway"
    assert claims.iat == tts.now
    assert claims.exp == tts.now + 60
    assert dict(claims.tctx) == {
        "source_account": "A",
        "destination_account": "B",
        "amount_minor": 10000,
        "currency": "USD",
    }
    assert claims.rctx["req_ip"] == "10.0.0.1"
    assert dict(claims.rctx["authn"]) == {"amr": ("pwd", "otp")}
    # txn-tokens-11 §13.4: the access token is never embedded.
    assert tts.form()["subject_token"] not in token


async def test_issuance_is_recorded_in_log_and_sink(tts):
    token = await tts.issue()
    claims = tts.verifier().verify(token).claims
    chain = await tts.log.chain(claims.txn)
    assert [record.event_type for record in chain] == ["token.issued"]
    issued = tts.sink.of_type(EventType.TOKEN_ISSUED)[0]
    assert issued.transaction_id == claims.txn
    assert issued.caller_workload == "api-gateway"
    assert len(issued.token_digest or "") == 64
    assert await tts.log.verify_integrity() == 1


async def test_unauthenticated_workload_is_rejected_txn_tokens_11_s11_5(tts):
    """txn-tokens-11 §11.5: the TTS MUST authenticate the workload."""
    response = await tts.post(tts.form(authenticate=False))
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"
    assert "WWW-Authenticate" in response.headers
    assert response.headers["cache-control"] == "no-store"
    assert last_denial(tts).reason_code is ReasonCode.WORKLOAD_UNAUTHENTICATED


async def test_assertion_signed_by_unregistered_key_is_rejected(tts):
    form = tts.form()
    form["client_assertion"] = tts.assertion(key=tts.keys["attacker"])
    response = await tts.post(form)
    assert response.status_code == 401
    assert last_denial(tts).reason_code is ReasonCode.WORKLOAD_UNAUTHENTICATED


async def test_registered_workload_without_policy_is_unauthorized(make_tts):
    def drop_gateway(config):
        del config["issuance_policy"]["workloads"]["api-gateway"]

    tts = make_tts(drop_gateway)
    response = await tts.post(tts.form())
    assert response.status_code == 400
    assert response.json()["error"] == "unauthorized_client"
    assert last_denial(tts).reason_code is ReasonCode.ISSUANCE_NOT_AUTHORIZED


async def test_unauthorized_scope_is_rejected_txn_tokens_11_s13_10(tts):
    """txn-tokens-11 §13.10: the workload's issuance policy limits its scopes."""
    response = await tts.post(tts.form(scope="ledger.write"))
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_scope"
    assert last_denial(tts).reason_code is ReasonCode.SCOPE_INSUFFICIENT


async def test_granted_scope_is_intersection_txn_tokens_11_s13_6(tts):
    """txn-tokens-11 §13.6: granted scope never exceeds the subject token's scope."""
    subject = tts.access_token(scope="payments.read")
    token = await tts.issue(subject_token=subject, scope="payments.read payments.transfer")
    assert str(tts.verifier().verify(token).claims.scope) == "payments.read"


async def test_scope_beyond_subject_scope_is_rejected_txn_tokens_11_s13_6(tts):
    """txn-tokens-11 §13.6."""
    subject = tts.access_token(scope="payments.read")
    response = await tts.post(tts.form(subject_token=subject, scope="payments.transfer"))
    assert response.json()["error"] == "invalid_scope"


async def test_scope_less_subject_token_is_rejected_txn_tokens_11_s13_14(tts):
    """txn-tokens-11 §13.14: unknown subject scope MUST NOT be treated as unconstrained."""
    subject = tts.access_token(scope=None)
    response = await tts.post(tts.form(subject_token=subject))
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_scope"
    assert last_denial(tts).reason_code is ReasonCode.SCOPE_INSUFFICIENT


async def test_expired_subject_token_is_rejected_txn_tokens_11_s6(tts):
    """txn-tokens-11 §6: MUST NOT issue if the presented credential has expired."""
    subject = tts.access_token(exp=tts.now - 1, iat=tts.now - 100)
    response = await tts.post(tts.form(subject_token=subject))
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"
    assert last_denial(tts).reason_code is ReasonCode.TOKEN_EXPIRED


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda t: t[:-4] + ("AAAA" if not t.endswith("AAAA") else "BBBB"), None),
        (lambda t: "not-a-jwt", ReasonCode.TOKEN_MALFORMED),
    ],
)
async def test_invalid_subject_token_is_rejected(tts, mutate, reason):
    response = await tts.post(tts.form(subject_token=mutate(tts.access_token())))
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"
    if reason is not None:
        assert last_denial(tts).reason_code is reason


async def test_subject_token_from_untrusted_issuer_is_rejected(tts):
    subject = tts.access_token(key=tts.keys["api-gateway"])
    response = await tts.post(tts.form(subject_token=subject))
    assert response.json()["error"] == "invalid_grant"
    assert last_denial(tts).reason_code is ReasonCode.KEY_UNKNOWN


async def test_issuance_policy_restricts_context_txn_tokens_11_s11_3(tts):
    """txn-tokens-11 §11.3: the TTS is authoritative for tctx and rctx."""
    token = await tts.issue(
        request_details={"amount_minor": 5, "currency": "EUR", "is_admin": True},
        request_context={"req_ip": "10.0.0.9", "authn": "forged", "role": "root"},
    )
    claims = tts.verifier().verify(token).claims
    assert dict(claims.tctx) == {"amount_minor": 5, "currency": "EUR"}
    assert claims.rctx["req_ip"] == "10.0.0.9"
    assert dict(claims.rctx["authn"]) == {"amr": ("pwd", "otp")}
    assert "role" not in claims.rctx
    event = tts.sink.of_type(EventType.TOKEN_ISSUED)[0]
    assert event.detail["dropped_keys"] == "tctx.is_admin,rctx.authn,rctx.role"


async def test_request_details_cannot_set_sub_or_txn(tts):
    """Attack: top-level claims never come from request_details or request_context."""
    token = await tts.issue(
        request_details={"sub": "user:mallory", "txn": "chosen", "aud": "elsewhere"},
        request_context={"sub": "user:mallory", "req_wl": "x"},
    )
    claims = tts.verifier().verify(token).claims
    assert claims.sub == "user:alice"
    assert claims.txn != "chosen"
    assert claims.aud == TRUST_DOMAIN
    assert claims.req_wl == "api-gateway"
    assert claims.tctx is None


async def test_mistyped_context_member_is_rejected(tts):
    """Strict comparison: "10000" and 10000.0 are not the integer 10000."""
    for amount in ("10000", 10000.0, True):
        response = await tts.post(tts.form(request_details={"amount_minor": amount}))
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_request"
        assert last_denial(tts).reason_code is ReasonCode.CLAIM_INVALID


async def test_subject_token_embedded_in_context_is_refused_txn_tokens_11_s13_4(tts):
    """txn-tokens-11 §13.4: the Txn-Token MUST NOT contain the access token."""
    subject = tts.access_token()
    response = await tts.post(
        tts.form(subject_token=subject, request_details={"currency": subject})
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


async def test_wrong_audience_is_invalid_target_txn_tokens_11_s11_1(tts):
    """txn-tokens-11 §11.1: audience MUST be the Trust Domain."""
    response = await tts.post(tts.form(audience="other.internal"))
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_target"
    assert last_denial(tts).reason_code is ReasonCode.TRUST_DOMAIN_MISMATCH


async def test_refresh_token_as_subject_is_rejected_txn_tokens_11_s13_3(tts):
    """txn-tokens-11 §11.2, §13.3: refresh tokens MUST NOT be used."""
    response = await tts.post(tts.form(subject_token_type=TOKEN_TYPE_REFRESH_TOKEN))
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"
    assert last_denial(tts).reason_code is ReasonCode.SUBJECT_TOKEN_INVALID


async def test_unsupported_subject_token_type_is_rejected(tts):
    response = await tts.post(tts.form(subject_token_type="urn:example:custom"))
    assert response.json()["error"] == "invalid_request"
    assert last_denial(tts).reason_code is ReasonCode.TOKEN_TYPE_INVALID


async def test_duplicate_form_parameters_are_rejected(tts):
    """Attack: parameter pollution (RFC 6749 §3.2)."""
    body = urlencode(tts.form()) + "&scope=ledger.write"
    response = await tts.post(body.encode())
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


async def test_oversized_body_is_rejected(tts):
    body = urlencode(tts.form(padding="x" * 40_000)).encode()
    response = await tts.post(body)
    assert response.status_code == 413
    assert response.json()["error"] == "invalid_request"
    assert last_denial(tts).reason_code is ReasonCode.TOKEN_MALFORMED


async def test_oversized_streamed_body_is_rejected(tts):
    """A body without Content-Length is still capped while streaming."""
    import httpx

    async def chunks():
        for _ in range(40):
            yield b"x" * 1024

    transport = httpx.ASGITransport(app=tts.app)
    async with httpx.AsyncClient(transport=transport, base_url="https://tts.test") as http:
        response = await http.post(
            "/token",
            content=chunks(),
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
    assert response.status_code == 413


async def test_missing_content_type_is_rejected(tts):
    response = await tts.post(
        urlencode(tts.form()).encode(), headers={"content-type": "text/plain"}
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"


async def test_wrong_grant_type_is_unsupported(tts):
    response = await tts.post(tts.form(grant_type="client_credentials"))
    assert response.json()["error"] == "unsupported_grant_type"


async def test_self_signed_subject_txn_tokens_11_s11_2_1(tts):
    """txn-tokens-11 §11.2.1: iss = requesting workload, aud = TTS, verified with its keys."""
    from pytrat.core.crypto import sign_compact

    key = tts.keys["payment-service"]
    subject = sign_compact(
        {
            "iss": "payment-service",
            "sub": "batch:nightly",
            "aud": "https://tts.payments.internal",
            "iat": tts.now,
            "exp": tts.now + 30,
            "scope": "ledger.write",
        },
        key.private_key,
        alg="ES256",
        kid=key.kid,
        typ="JWT",
    )
    token = await tts.issue(
        workload="payment-service",
        subject_token=subject,
        subject_token_type=TOKEN_TYPE_SELF_SIGNED,
        scope="ledger.write",
    )
    claims = tts.verifier().verify(token).claims
    assert claims.sub == "batch:nightly"
    assert claims.exp == tts.now + 30  # capped at the subject's exp
    assert claims.rctx is None


async def test_unsigned_json_subject_only_for_allowed_workload_txn_tokens_11_s11_2_2(tts):
    """txn-tokens-11 §11.2.2, disabled unless the workload is listed."""
    subject = '{"sub": "job:42", "scope": "payments.read"}'
    denied = await tts.post(
        tts.form(subject_token=subject, subject_token_type=TOKEN_TYPE_UNSIGNED_JSON)
    )
    assert denied.json()["error"] == "unauthorized_client"
    token = await tts.issue(
        workload="payment-service",
        subject_token=subject,
        subject_token_type=TOKEN_TYPE_UNSIGNED_JSON,
        scope="payments.read",
    )
    assert tts.verifier().verify(token).claims.sub == "job:42"


async def test_rate_limit_returns_429(make_tts):
    def tight(config):
        config["rate_limit"] = {"requests_per_second": 0.001, "burst": 1}

    tts = make_tts(tight)
    assert (await tts.post(tts.form())).status_code == 200
    response = await tts.post(tts.form())
    assert response.status_code == 429
    assert response.json()["error"] == "slow_down"
    assert last_denial(tts).reason_code is ReasonCode.RATE_LIMITED


async def test_healthz_and_unknown_routes(tts):
    assert (await tts.get("/healthz")).json() == {"status": "ok"}
    assert (await tts.get("/docs")).status_code == 404
    assert (await tts.get("/openapi.json")).status_code == 404


async def test_internal_error_does_not_leak(tts, caplog):
    class Boom:
        def authenticate(self, request, headers, peer):
            raise RuntimeError("secret internal detail")

    from dataclasses import replace

    from pytrat.server import create_app

    tts.app = create_app(replace(tts.components, authenticator=Boom()))
    response = await tts.post(tts.form())
    assert response.status_code == 500
    assert response.json() == {"error": "server_error", "error_description": "internal error"}
    assert "secret internal detail" not in caplog.text


async def test_issuance_log_failure_withholds_token(tts):
    from dataclasses import replace

    from pytrat.core import DependencyError
    from pytrat.server import create_app

    class BrokenLog:
        async def append(self, event, claims_digest):
            raise DependencyError("down")

        async def chain(self, txn):
            return []

        async def replacement_count(self, txn):
            return 0

    tts.app = create_app(replace(tts.components, log=BrokenLog()))
    response = await tts.post(tts.form())
    assert response.status_code == 503
    assert response.json()["error"] == "temporarily_unavailable"
    assert "access_token" not in response.json()
