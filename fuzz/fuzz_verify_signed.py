"""Structure-aware fuzzing of ``TokenVerifier.verify`` past the signature check.

The fuzzer writes the JOSE header and payload; the harness signs them with the trusted key, so
every input reaches header checks, strict payload decoding and claim validation.

Input layout: ``mode byte || header bytes || NUL || payload bytes``.

* mode 0: header and payload are raw bytes.
* mode 1: a valid header; the payload is a JSON object of overrides on a valid claim set.
* mode 2: both header and payload are JSON overrides on valid ones.

Invariants: only :class:`TokenError` is raised, and an accepted token satisfies every check the
verifier promises (Trust Domain, lifetime bounds, ``kid``).
"""

from __future__ import annotations

import json
from collections.abc import Iterator

from fuzz._harness import (
    NOW,
    TRUST_DOMAIN,
    assert_no_token,
    choose,
    clock,
    fuzz,
    join,
    key,
    overlay,
    sign_segments,
    split,
)
from pytrat.core import TXN_TOKEN_TYP, TokenError, VerifiedToken
from pytrat.core.testing import TokenFactory

SIGNER = key("fuzz-tts")
FACTORY = TokenFactory(key=SIGNER, trust_domain=TRUST_DOMAIN, clock=clock())
VERIFIER = FACTORY.verifier()
SETTINGS = VERIFIER.settings
HEADER: dict[str, object] = {"typ": TXN_TOKEN_TYP, "alg": SIGNER.alg, "kid": SIGNER.kid}
CLAIMS = FACTORY.claims(txn="txn-fuzz")
_MODES = (0, 1, 2)


def _build(data: bytes) -> str:
    mode, rest = choose(data, _MODES)
    raw_header, raw_payload = split(rest, 2)
    if mode == 0:
        return sign_segments(raw_header, raw_payload, SIGNER)
    header = json.dumps(HEADER).encode() if mode == 1 else overlay(HEADER, raw_header)
    return sign_segments(header, overlay(CLAIMS, raw_payload), SIGNER)


def _check_accepted(verified: VerifiedToken) -> None:
    claims = verified.claims
    leeway = SETTINGS.leeway.total_seconds()
    if claims.aud != TRUST_DOMAIN:
        raise AssertionError("accepted a token for another Trust Domain")
    if verified.kid != SIGNER.kid or verified.alg != SIGNER.alg:
        raise AssertionError("accepted a token with an unexpected key or algorithm")
    if claims.iat > NOW + leeway or claims.exp + leeway <= NOW:
        raise AssertionError("accepted a token outside its validity window")
    if not 0 < claims.exp - claims.iat <= SETTINGS.max_lifetime.total_seconds():
        raise AssertionError("accepted a token whose lifetime exceeds the maximum")


def TestOneInput(data: bytes) -> None:  # noqa: N802 - name required by Atheris
    """Sign the fuzzer's header and payload, then verify."""
    token = _build(data)
    try:
        verified = VERIFIER.verify(token)
    except TokenError as error:
        assert_no_token(error)
        return
    _check_accepted(verified)


def seeds() -> Iterator[bytes]:
    """A valid token in every mode plus representative near-misses."""
    header = json.dumps(HEADER).encode()
    payload = json.dumps(CLAIMS).encode()
    yield bytes([0]) + join(header, payload)
    yield bytes([0]) + join(header, b'{"aud":"a","aud":"b"}')
    yield bytes([0]) + join(header, b"[]")
    yield bytes([1]) + join(b"", b"{}")
    yield bytes([1]) + join(b"", b'{"aud": ["payments.internal"]}')
    yield bytes([1]) + join(b"", b'{"exp": 1795000600}')
    yield bytes([1]) + join(b"", b'{"iat": 1795000000.0}')
    yield bytes([1]) + join(b"", b'{"scope": "a  b"}')
    yield bytes([1]) + join(b"", b'{"tctx": {"amount_minor": [[[[[[[[1]]]]]]]]}}')
    yield bytes([1]) + join(
        b"",
        b'{"agentic_ctx": {"originator": {"id": "a"}, "proximate_agent": {"id": "b"},'
        b' "chain_metadata": {"hop_count": 1}}}',
    )
    # Regression: deeply nested tctx raised RecursionError instead of TokenError.
    yield bytes([1]) + join(b"", b'{"tctx": {"a": ' + b"[" * 600 + b"]" * 600 + b"}}")
    yield bytes([2]) + join(b'{"typ": "JWT"}', b"{}")
    yield bytes([2]) + join(b'{"kid": null}', b"{}")
    yield bytes([2]) + join(b'{"crit": ["exp"]}', b"{}")


if __name__ == "__main__":
    fuzz(TestOneInput)
