"""Property-based fuzzing of every parser that sees untrusted input.

The invariant is the same everywhere: arbitrary input produces either a value or a *specific*
PyTraT error, never an unexpected exception type (which would surface as a 500 or, worse, an
unhandled path that skips a check).
"""

from __future__ import annotations

import base64
import contextlib
import json

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pytrat.core import (
    ConfigurationError,
    ContextBinding,
    InboundRequest,
    PyTraTError,
    StaticKeySet,
    TokenError,
    WorkloadJwtAuthenticator,
    parse_claims,
)
from pytrat.core.testing import TokenFactory

pytestmark = pytest.mark.security

FACTORY = TokenFactory.create()
VERIFIER = FACTORY.verifier()
FUZZ = settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])

json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=12),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=8), children, max_size=4)
    ),
    max_leaves=20,
)


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@FUZZ
@given(st.text(max_size=400))
def test_verifier_on_arbitrary_text(raw: str) -> None:
    with pytest.raises(TokenError):
        VERIFIER.verify(raw)


@FUZZ
@given(json_values, json_values)
def test_verifier_on_arbitrary_header_and_payload(header: object, payload: object) -> None:
    token = f"{b64(json.dumps(header).encode())}.{b64(json.dumps(payload).encode())}.c2ln"
    with pytest.raises(TokenError):
        VERIFIER.verify(token)


@FUZZ
@given(
    st.dictionaries(
        st.sampled_from(
            ["aud", "txn", "sub", "scope", "req_wl", "iat", "exp", "tctx", "agentic_ctx", "act"]
        ),
        json_values,
    )
)
def test_signed_arbitrary_claims_never_crash(claims: dict[str, object]) -> None:
    """Correctly signed but arbitrary payloads: accepted only if fully valid, else TokenError."""
    token = FACTORY.mint_payload(claims)
    try:
        verified = VERIFIER.verify(token)
    except TokenError:
        return
    assert verified.claims.aud == "payments.internal"


@FUZZ
@given(st.dictionaries(st.text(max_size=10), json_values, max_size=8))
def test_parse_claims_raises_only_token_errors(payload: dict[str, object]) -> None:
    with contextlib.suppress(TokenError):
        parse_claims(payload)


@FUZZ
@given(json_values)
def test_jwks_parser_raises_only_configuration_errors(document: object) -> None:
    with contextlib.suppress(ConfigurationError):
        StaticKeySet.from_jwks_bytes(json.dumps(document).encode())


@FUZZ
@given(st.binary(max_size=300))
def test_jwks_parser_on_bytes(data: bytes) -> None:
    with contextlib.suppress(ConfigurationError):
        StaticKeySet.from_jwks_bytes(data)


@FUZZ
@given(json_values, json_values)
def test_binding_raises_only_pytrat_errors(tctx: object, request_data: object) -> None:
    binding = ContextBinding.compile(["amount_minor", "nested.value"])
    with contextlib.suppress(PyTraTError):
        binding.check(
            tctx if isinstance(tctx, dict) else {"amount_minor": tctx},
            request_data if isinstance(request_data, dict) else {"amount_minor": request_data},
        )


@FUZZ
@given(
    st.lists(st.tuples(st.text(max_size=20), st.text(max_size=200)), max_size=6),
    st.text(max_size=20),
)
def test_workload_authenticator_raises_only_pytrat_errors(headers, peer: str) -> None:
    authenticator = WorkloadJwtAuthenticator(FACTORY.key.key_set(), audience="svc")
    with contextlib.suppress(PyTraTError):
        authenticator.authenticate(InboundRequest(tuple(headers), peer))
