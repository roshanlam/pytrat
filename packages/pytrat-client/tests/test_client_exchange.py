"""Pure exchange logic: request building (§11.1), response parsing (§11.4), RFC 6749 §5.2 errors."""

from __future__ import annotations

import json
from urllib.parse import parse_qs

import pytest

from pytrat.client import (
    ExchangeError,
    ExchangeRequest,
    build_issue_request,
    build_replacement_request,
    check_replacement,
    parse_exchange_response,
)
from pytrat.client.exchange import MAX_EXCHANGE_RESPONSE_BYTES
from pytrat.core import AuthorizationError, ReasonCode, Scope, SecretToken, TokenError
from pytrat.core.constants import (
    GRANT_TYPE_TOKEN_EXCHANGE,
    TOKEN_TYPE_ACCESS_TOKEN,
    TOKEN_TYPE_REFRESH_TOKEN,
    TOKEN_TYPE_TXN_TOKEN,
)

JSON = {"content-type": "application/json"}
SUBJECT = SecretToken("subject-access-token-value")


def _body(**overrides: object) -> bytes:
    body: dict[str, object] = {
        "access_token": "eyJ.header.sig",
        "issued_token_type": TOKEN_TYPE_TXN_TOKEN,
        "token_type": "N_A",
        **overrides,
    }
    return json.dumps({k: v for k, v in body.items() if v is not None}).encode()


def _issue(**overrides: object) -> ExchangeRequest:
    args: dict[str, object] = {
        "audience": "payments.internal",
        "scope": "payments.transfer",
        "subject_token": SUBJECT,
        "subject_token_type": TOKEN_TYPE_ACCESS_TOKEN,
        **overrides,
    }
    return build_issue_request(**args)  # type: ignore[arg-type]


# ----------------------------------------------------------------------------- §11.1 requests


def test_issue_request_carries_the_required_parameters_section_11_1() -> None:
    request = _issue()
    assert dict(request.form) == {
        "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
        "requested_token_type": TOKEN_TYPE_TXN_TOKEN,
        "audience": "payments.internal",
        "scope": "payments.transfer",
        "subject_token": SUBJECT.reveal(),
        "subject_token_type": TOKEN_TYPE_ACCESS_TOKEN,
    }
    assert request.headers["Content-Type"] == "application/x-www-form-urlencoded"


def test_request_context_is_url_encoded_compact_json_not_base64_section_11_1() -> None:
    request = _issue(
        request_context={"ip": "10.0.0.1", "nested": {"b": 1, "a": [1, 2]}},
        request_details={"amount": 100},
    )
    assert request.form["request_context"] == '{"ip":"10.0.0.1","nested":{"a":[1,2],"b":1}}'
    assert request.form["request_details"] == '{"amount":100}'
    body = request.body().decode()
    assert "request_context=%7B%22ip%22" in body
    parsed = parse_qs(body)
    assert json.loads(parsed["request_context"][0])["ip"] == "10.0.0.1"


def test_scope_object_is_serialised_canonically() -> None:
    assert _issue(scope=Scope.of("b", "a")).form["scope"] == "a b"


@pytest.mark.parametrize("scope", ["", "a  b", 'bad"scope'])
def test_invalid_scope_is_rejected(scope: str) -> None:
    with pytest.raises(TokenError) as excinfo:
        _issue(scope=scope)
    assert excinfo.value.reason is ReasonCode.CLAIM_INVALID


def test_refresh_token_subject_is_refused_before_sending_section_11_2() -> None:
    with pytest.raises(ExchangeError) as excinfo:
        _issue(subject_token_type=TOKEN_TYPE_REFRESH_TOKEN)
    assert excinfo.value.reason is ReasonCode.SUBJECT_TOKEN_INVALID


def test_empty_subject_token_type_is_refused() -> None:
    with pytest.raises(ExchangeError) as excinfo:
        _issue(subject_token_type="")
    assert excinfo.value.reason is ReasonCode.SUBJECT_TOKEN_INVALID


def test_empty_audience_is_refused() -> None:
    with pytest.raises(ExchangeError) as excinfo:
        _issue(audience="")
    assert excinfo.value.reason is ReasonCode.EXCHANGE_FAILED


def test_raw_string_subject_token_is_refused() -> None:
    with pytest.raises(TypeError):
        _issue(subject_token="raw")


@pytest.mark.parametrize("bad", [["not", "an", "object"], {"x": {1, 2}}, {"x": float("nan")}])
def test_request_context_must_be_a_json_object(bad: object) -> None:
    with pytest.raises(ExchangeError) as excinfo:
        _issue(request_context=bad)
    assert excinfo.value.reason is ReasonCode.EXCHANGE_FAILED


def test_exchange_request_is_immutable_and_masks_secrets() -> None:
    request = _issue()
    with pytest.raises(TypeError):
        request.form["scope"] = "admin"  # type: ignore[index]
    extended = request.with_form({"client_assertion": "assertion-secret"})
    assert "client_assertion" not in request.form
    for text in (repr(request), repr(extended), str(extended)):
        assert SUBJECT.reveal() not in text
        assert "assertion-secret" not in text
        assert "subject_token" in text


# ----------------------------------------------------------------------------- replacement


def test_replacement_presents_current_token_as_txn_token_subject_profile_p4(current) -> None:
    request = build_replacement_request(current)
    assert request.form["subject_token"] == current.forwardable.reveal()
    assert request.form["subject_token_type"] == TOKEN_TYPE_TXN_TOKEN
    assert request.form["audience"] == current.claims.aud
    assert request.form["scope"] == "payments.read payments.transfer"


def test_replacement_may_narrow_scope(current) -> None:
    request = build_replacement_request(
        current, scope=Scope.of("payments.read"), request_details={"step": 2}
    )
    assert request.form["scope"] == "payments.read"
    assert request.form["request_details"] == '{"step":2}'


def test_replacement_request_cannot_widen_scope_section_13_15(current) -> None:
    with pytest.raises(AuthorizationError) as excinfo:
        build_replacement_request(current, scope=Scope.of("payments.read", "admin"))
    assert excinfo.value.reason is ReasonCode.REPLACEMENT_WIDENS_AUTHORIZATION


def test_replacement_of_unverified_value_is_refused() -> None:
    with pytest.raises(TypeError):
        build_replacement_request("raw.token.value")  # type: ignore[arg-type]


AGENTIC = {
    "originator": {"id": "agent-root"},
    "proximate_agent": {"id": "agent-1"},
    "chain_metadata": {"hop_count": 2},
}


def test_check_replacement_accepts_attenuation(factory, verifier) -> None:
    old = verifier.verify(factory.mint(txn="t1", scope="a b", agentic_ctx=AGENTIC))
    new_ctx = {**AGENTIC, "chain_metadata": {"hop_count": 3}}
    new = verifier.verify(factory.mint(txn="t1", scope="a", agentic_ctx=new_ctx))
    check_replacement(old, new)


@pytest.mark.parametrize(
    ("old_claims", "new_claims", "what"),
    [
        ({"txn": "t1"}, {"txn": "t2"}, "txn"),
        ({"txn": "t1"}, {"txn": "t1", "sub": "user:999"}, "sub"),
        ({"txn": "t1"}, {"txn": "t1", "act": {"sub": "intruder"}}, "act"),
        ({"txn": "t1", "scope": "a"}, {"txn": "t1", "scope": "a b"}, "scope"),
        ({"txn": "t1", "agentic_ctx": AGENTIC}, {"txn": "t1"}, "agentic_ctx"),
        (
            {"txn": "t1", "agentic_ctx": AGENTIC},
            {"txn": "t1", "agentic_ctx": {**AGENTIC, "originator": {"id": "other"}}},
            "originator",
        ),
        (
            {"txn": "t1", "agentic_ctx": AGENTIC},
            {"txn": "t1", "agentic_ctx": {**AGENTIC, "chain_metadata": {"hop_count": 1}}},
            "hop_count",
        ),
    ],
)
def test_tts_replacement_that_widens_or_swaps_identity_is_rejected(
    factory, verifier, old_claims, new_claims, what
) -> None:
    old = verifier.verify(factory.mint(**old_claims))
    new = verifier.verify(factory.mint(**new_claims))
    with pytest.raises(AuthorizationError) as excinfo:
        check_replacement(old, new)
    assert excinfo.value.reason is ReasonCode.REPLACEMENT_WIDENS_AUTHORIZATION
    assert what in excinfo.value.detail


# ----------------------------------------------------------------------------- §11.4 responses


def test_conforming_response_yields_the_token_section_11_4() -> None:
    token = parse_exchange_response(200, JSON, _body())
    assert token == SecretToken("eyJ.header.sig")


@pytest.mark.parametrize("token_type", ["N_A", "n_a", "N_a"])
def test_token_type_n_a_is_case_insensitive_section_11_4(token_type: str) -> None:
    parse_exchange_response(200, JSON, _body(token_type=token_type))


def test_content_type_parameters_are_accepted() -> None:
    parse_exchange_response(200, {"Content-Type": "application/json; charset=utf-8"}, _body())


@pytest.mark.parametrize(
    "overrides",
    [
        {"token_type": "Bearer"},
        {"token_type": None},
        {"token_type": 1},
        {"issued_token_type": TOKEN_TYPE_ACCESS_TOKEN},
        {"issued_token_type": None},
        {"access_token": ""},
        {"access_token": None},
        {"access_token": ["a"]},
    ],
    ids=lambda o: ",".join(f"{k}={v!r}" for k, v in o.items()),
)
def test_non_conforming_success_response_is_rejected_section_11_4(overrides) -> None:
    with pytest.raises(ExchangeError) as excinfo:
        parse_exchange_response(200, JSON, _body(**overrides))
    assert excinfo.value.reason is ReasonCode.EXCHANGE_FAILED


def test_response_carrying_refresh_token_is_rejected_section_11_4() -> None:
    with pytest.raises(ExchangeError) as excinfo:
        parse_exchange_response(200, JSON, _body(refresh_token="long-lived"))
    assert "refresh_token" in excinfo.value.detail
    assert "long-lived" not in str(excinfo.value)


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b"[1, 2]",
        b'{"access_token": "a", "access_token": "b"}',
        b'{"token_type": NaN}',
        b"\xff\xfe",
    ],
)
def test_malformed_or_ambiguous_json_is_rejected(body: bytes) -> None:
    with pytest.raises(ExchangeError):
        parse_exchange_response(200, JSON, body)


@pytest.mark.parametrize("headers", [{}, {"content-type": "text/html"}])
def test_success_response_must_be_json(headers) -> None:
    with pytest.raises(ExchangeError):
        parse_exchange_response(200, headers, _body())


def test_oversized_response_is_rejected_before_parsing() -> None:
    with pytest.raises(ExchangeError) as excinfo:
        parse_exchange_response(200, JSON, b" " * (MAX_EXCHANGE_RESPONSE_BYTES + 1))
    assert "size" in excinfo.value.detail


@pytest.mark.parametrize("status", [201, 204, 302, 500])
def test_non_200_status_is_an_error_even_with_a_token(status: int) -> None:
    with pytest.raises(ExchangeError) as excinfo:
        parse_exchange_response(status, JSON, _body())
    assert excinfo.value.status_code == status
    assert excinfo.value.oauth_error is None


# ----------------------------------------------------------------------------- RFC 6749 §5.2


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (400, "invalid_request"),
        (401, "invalid_client"),
        (400, "invalid_grant"),
        (400, "unauthorized_client"),
        (400, "unsupported_grant_type"),
        (400, "invalid_scope"),
        (400, "invalid_target"),  # RFC 8693 §2.2.2
        (503, "temporarily_unavailable"),
    ],
)
def test_oauth_error_response_maps_to_exchange_failed_rfc6749_5_2(status: int, code: str) -> None:
    body = json.dumps({"error": code, "error_description": "nope"}).encode()
    with pytest.raises(ExchangeError) as excinfo:
        parse_exchange_response(status, JSON, body)
    error = excinfo.value
    assert error.reason is ReasonCode.EXCHANGE_FAILED
    assert error.oauth_error == code
    assert error.oauth_error_description == "nope"
    assert error.status_code == status
    assert code in error.detail
    assert error.http_status == 502


@pytest.mark.parametrize(
    "body",
    [b"<html>bad gateway</html>", b'{"error": 42}', b'{"error": "bad\\"quote"}', b"{}", b"[]"],
)
def test_unusable_error_bodies_yield_no_oauth_error(body: bytes) -> None:
    with pytest.raises(ExchangeError) as excinfo:
        parse_exchange_response(400, JSON, body)
    assert excinfo.value.oauth_error is None
    assert excinfo.value.oauth_error_description is None


def test_error_description_is_sanitised_and_truncated() -> None:
    description = "bad\x00line\nbreak ☃ " + "x" * 500
    body = json.dumps({"error": "invalid_request", "error_description": description}).encode()
    with pytest.raises(ExchangeError) as excinfo:
        parse_exchange_response(400, JSON, body)
    text = excinfo.value.oauth_error_description
    assert text is not None
    assert len(text) <= 200
    assert "\x00" not in text
    assert "\n" not in text
    assert "☃" not in text


def test_secrets_echoed_by_tts_are_redacted_from_errors() -> None:
    jwt_like = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1c2VyOjEyMyJ9.c2lnbmF0dXJlLXZhbHVlLWhlcmU"
    short_secret = SecretToken("opaque-42")
    body = json.dumps(
        {
            "error": "invalid_grant",
            "error_description": f"bad token {jwt_like} and {short_secret.reveal()}",
        }
    ).encode()
    with pytest.raises(ExchangeError) as excinfo:
        parse_exchange_response(400, JSON, body, redact=[short_secret])
    error = excinfo.value
    for rendered in (str(error), repr(error), error.oauth_error_description or ""):
        assert jwt_like not in rendered
        assert "opaque-42" not in rendered
    assert "[redacted]" in (error.oauth_error_description or "")
