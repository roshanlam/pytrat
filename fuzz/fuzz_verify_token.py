"""Fuzz ``TokenVerifier.verify`` with arbitrary ``Txn-Token`` header values.

Invariant: every input is rejected with :class:`TokenError` (nothing the fuzzer writes carries a
valid ES256 signature), and no error message contains a token.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Iterator

from fuzz._harness import TRUST_DOMAIN, assert_no_token, clock, fuzz, key, text
from pytrat.core import TXN_TOKEN_TYP, TokenError
from pytrat.core.testing import TokenFactory, b64url

FACTORY = TokenFactory(key=key("fuzz-tts"), trust_domain=TRUST_DOMAIN, clock=clock())
VERIFIER = FACTORY.verifier()


def TestOneInput(data: bytes) -> None:  # noqa: N802 - name required by Atheris
    """Verify one fuzzer-supplied token."""
    try:
        VERIFIER.verify(text(data))
    except TokenError as error:
        assert_no_token(error)
        return
    raise AssertionError("a token without a valid signature was accepted")


def seeds() -> Iterator[bytes]:
    """Structurally plausible tokens with invalid signatures."""
    fake_signature = b64url(bytes(64))
    payload = b64url(json.dumps(FACTORY.claims(txn="txn-seed")).encode())
    headers: list[dict[str, object]] = [
        {"typ": TXN_TOKEN_TYP, "alg": "ES256", "kid": "fuzz-tts"},
        {"typ": TXN_TOKEN_TYP, "alg": "none", "kid": "fuzz-tts"},
        {"typ": TXN_TOKEN_TYP, "alg": "HS256", "kid": "fuzz-tts"},
        {"typ": TXN_TOKEN_TYP, "alg": "ES256", "jwk": {"kty": "EC"}},
        {"typ": "JWT", "alg": "ES256", "kid": "fuzz-tts"},
        {"typ": TXN_TOKEN_TYP, "alg": "ES256", "kid": "../../etc/passwd"},
    ]
    for header in headers:
        yield f"{b64url(json.dumps(header).encode())}.{payload}.{fake_signature}".encode()
    duplicate_alg = b64url(b'{"typ":"txntoken+jwt","alg":"ES256","alg":"none"}')
    yield f"{duplicate_alg}.{payload}.{fake_signature}".encode()
    yield f"{b64url(json.dumps(headers[0]).encode())}.{payload}.".encode()
    yield base64.b64encode(b"not a token")
    yield b"a.b.c"
    yield b""


if __name__ == "__main__":
    fuzz(TestOneInput)
