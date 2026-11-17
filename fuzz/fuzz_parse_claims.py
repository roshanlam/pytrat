"""Fuzz ``parse_claims`` with strictly decoded JSON payloads.

Input layout: ``mode byte || JSON``. Mode 0 parses the JSON object as the whole payload; mode 1
applies it as overrides to a valid claim set so the fuzzer explores individual claims.

Invariants: only :class:`TokenError` is raised; an accepted claim set survives a
``to_payload`` → ``parse_claims`` round trip unchanged.
"""

from __future__ import annotations

from collections.abc import Iterator

from fuzz._harness import TRUST_DOMAIN, choose, clock, fuzz, key, overlay
from pytrat.core import TokenError, parse_claims, strict_loads
from pytrat.core.testing import TokenFactory

CLAIMS = TokenFactory(key=key("fuzz-tts"), trust_domain=TRUST_DOMAIN, clock=clock()).claims(
    txn="txn-fuzz"
)


def TestOneInput(data: bytes) -> None:  # noqa: N802 - name required by Atheris
    """Decode the payload as the verifier does, then parse the claims."""
    mode, rest = choose(data, (0, 1))
    raw_payload = rest if mode == 0 else overlay(CLAIMS, rest)
    try:
        payload = strict_loads(raw_payload)
    except ValueError:
        return
    if not isinstance(payload, dict):
        return
    try:
        claims = parse_claims(payload)
    except TokenError:
        return
    if parse_claims(claims.to_payload()) != claims:
        raise AssertionError("claims changed across a serialisation round trip")


def seeds() -> Iterator[bytes]:
    """The valid claim set and claim-level variations."""
    yield bytes([0]) + b"{}"
    yield (
        bytes([0])
        + b'{"aud": "x", "txn": "t", "sub": "s", "scope": "a", "req_wl": "w",'
        + (b' "iat": 1, "exp": 2}')
    )
    yield bytes([1]) + b"{}"
    yield bytes([1]) + b'{"iat": true}'
    yield bytes([1]) + b'{"exp": 9007199254740993}'
    yield bytes([1]) + b'{"scope": ""}'
    yield bytes([1]) + b'{"tctx": []}'
    yield bytes([1]) + b'{"act": {"sub": "agent"}}'
    yield (
        bytes([1])
        + b'{"agentic_ctx": {"originator": {"id": "a", "session_id": "s"},'
        + (b' "proximate_agent": {"id": "b"}, "chain_metadata": {"hop_count": 0}}}')
    )
    yield bytes([1]) + b'{"unknown": {"nested": [1, 2, 3]}}'
    # Regression: deeply nested tctx raised RecursionError instead of TokenError.
    yield bytes([1]) + b'{"tctx": {"a": ' + b"[" * 600 + b"]" * 600 + b"}}"


if __name__ == "__main__":
    fuzz(TestOneInput)
