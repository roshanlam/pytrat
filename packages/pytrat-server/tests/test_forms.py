"""Form parsing (txn-tokens-11 §11.1)."""

from __future__ import annotations

import contextlib
from urllib.parse import urlencode

import pytest
from hypothesis import given
from hypothesis import strategies as st

from pytrat.core import ReasonCode
from pytrat.core.constants import (
    GRANT_TYPE_TOKEN_EXCHANGE,
    TOKEN_TYPE_ACCESS_TOKEN,
    TOKEN_TYPE_REFRESH_TOKEN,
    TOKEN_TYPE_TXN_TOKEN,
)
from pytrat.server import OAuthError, parse_token_request
from pytrat.server.forms import parse_json_object

CT = "application/x-www-form-urlencoded"


def fields(**overrides):
    data = {
        "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
        "requested_token_type": TOKEN_TYPE_TXN_TOKEN,
        "audience": "payments.internal",
        "scope": "b a",
        "subject_token": "subject-token-value",
        "subject_token_type": TOKEN_TYPE_ACCESS_TOKEN,
    }
    for name, value in overrides.items():
        if value is None:
            data.pop(name, None)
        else:
            data[name] = value
    return data


def parse(body=None, content_type=CT, max_bytes=4096, **overrides):
    raw = body if body is not None else urlencode(fields(**overrides)).encode()
    return parse_token_request(raw, content_type, max_bytes=max_bytes)


def rejected(**kwargs):
    with pytest.raises(OAuthError) as info:
        parse(**kwargs)
    return info.value


def test_valid_request_is_typed():
    request = parse(
        request_context='{"req_ip": "1.2.3.4"}',
        request_details='{"a": {"b": [1, 2]}}',
        client_id="api-gateway",
    )
    assert str(request.scope) == "a b"
    assert request.subject_token.reveal() == "subject-token-value"
    assert "subject-token-value" not in repr(request)
    assert request.request_context["req_ip"] == "1.2.3.4"
    assert request.request_details["a"]["b"] == (1, 2)
    assert request.client.client_id == "api-gateway"
    assert request.client.client_assertion is None
    assert not request.is_replacement
    assert parse(subject_token_type=TOKEN_TYPE_TXN_TOKEN).is_replacement


@pytest.mark.parametrize("content_type", [CT, f"{CT}; charset=UTF-8", f'{CT};charset="utf-8"'])
def test_content_type_variants_accepted(content_type):
    assert parse(content_type=content_type).audience == "payments.internal"


@pytest.mark.parametrize("content_type", [None, "application/json", f"{CT}; charset=latin-1"])
def test_content_type_required(content_type):
    assert rejected(content_type=content_type).error == "invalid_request"


def test_oversize_body_is_413():
    error = rejected(max_bytes=10)
    assert (error.error, error.status) == ("invalid_request", 413)


@pytest.mark.parametrize("body", [b"a=1&&b=2", b"novalue", "scope=é".encode(), b"x=%ff"])
def test_malformed_encoding_rejected(body):
    assert rejected(body=body).reason is ReasonCode.TOKEN_MALFORMED


def test_duplicate_parameters_rejected():
    body = urlencode(fields()) + "&audience=evil.internal"
    assert rejected(body=body.encode()).error == "invalid_request"


def test_too_many_fields_rejected():
    body = urlencode(fields()) + "".join(f"&x{i}=1" for i in range(40))
    assert rejected(body=body.encode()).error == "invalid_request"


@pytest.mark.parametrize(
    "missing",
    [
        "grant_type",
        "requested_token_type",
        "audience",
        "scope",
        "subject_token",
        "subject_token_type",
    ],
)
def test_required_parameters_txn_tokens_11_s11_1(missing):
    """txn-tokens-11 §11.1: all six parameters are REQUIRED."""
    error = rejected(**{missing: None})
    assert error.error == "invalid_request"
    assert error.reason is ReasonCode.CLAIM_MISSING


def test_empty_parameter_counts_as_missing():
    assert rejected(scope="").reason is ReasonCode.CLAIM_MISSING


def test_grant_type_must_be_token_exchange_txn_tokens_11_s11_1():
    """txn-tokens-11 §11.1."""
    assert rejected(grant_type="password").error == "unsupported_grant_type"


def test_requested_token_type_must_be_txn_token_txn_tokens_11_s11_1():
    """txn-tokens-11 §11.1."""
    error = rejected(requested_token_type=TOKEN_TYPE_ACCESS_TOKEN)
    assert (error.error, error.reason) == ("invalid_request", ReasonCode.TOKEN_TYPE_INVALID)


def test_refresh_token_subject_rejected_txn_tokens_11_s11_2():
    """txn-tokens-11 §11.2, §13.3."""
    error = rejected(subject_token_type=TOKEN_TYPE_REFRESH_TOKEN)
    assert error.reason is ReasonCode.SUBJECT_TOKEN_INVALID


@pytest.mark.parametrize("scope", ["a  b", " a", "a\tb", 'a"b'])
def test_invalid_scope_syntax(scope):
    assert rejected(scope=scope).error == "invalid_scope"


@pytest.mark.parametrize("name", ["actor_token", "actor_token_type", "resource"])
def test_unsupported_rfc8693_parameters_refused(name):
    assert rejected(**{name: "x"}).error == "invalid_request"


def test_client_secret_refused():
    error = rejected(client_secret="s3cret")
    assert (error.error, error.status) == ("invalid_client", 401)


def test_unknown_parameters_ignored():
    assert parse(extension="x").audience == "payments.internal"


@pytest.mark.parametrize(
    "raw",
    [
        "[1]",
        '"s"',
        '{"a":1,"a":2}',
        '{"a": NaN}',
        # Regression: decoded to inf, which could not be signed later.
        '{"a": 1e400}',
        "{",
        "[" * 50 + "]" * 50,
        '{"a":' * 20 + "1" + "}" * 20,
        # Regression: lone surrogates crashed request_details hashing (500).
        '{"\\ud800": 1}',
        '{"a": "\\udfff"}',
    ],
)
def test_context_must_be_strict_object(raw):
    error = rejected(request_details=raw)
    assert (error.error, error.reason) == ("invalid_request", ReasonCode.CLAIM_INVALID)
    error = rejected(request_context=raw)
    assert error.reason is ReasonCode.CLAIM_INVALID


def test_parse_json_object_deep_recursion():
    with pytest.raises(ValueError, match=r"too deep|object"):
        parse_json_object("[" * 100_000 + "]" * 100_000)


def test_oauth_error_repr_is_safe():
    error = rejected(grant_type="password")
    assert "unsupported_grant_type" in repr(error)


@given(st.binary(max_size=512))
def test_parser_never_raises_anything_but_oauth_error(body):
    with contextlib.suppress(OAuthError):
        parse(body=body)
