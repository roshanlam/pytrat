"""Fuzz the TTS subject-token validators (txn-tokens-11 §11.2).

Input layout: ``validator byte || mode byte || header || NUL || payload``.

* validator: JWT access token, self-signed JWT or unsigned JSON.
* mode 0: ``header`` is the raw subject token (``payload`` is ignored).
* mode 1: header and payload are JSON overrides on a valid subject, signed with the key the
  validator trusts (for unsigned JSON, the payload overrides a valid unsigned subject).

Invariants: only :class:`OAuthError` is raised; an accepted subject has a ``sub``, has not
expired, and a requester-asserted subject (self-signed, unsigned) never carries ``act``
(PyTraT profile P28).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass

from fuzz._harness import (
    NOW,
    assert_no_token,
    choose,
    clock,
    fuzz,
    join,
    key,
    overlay,
    sign_segments,
    split,
    text,
)
from pytrat.core import SecretToken
from pytrat.core.testing import TestKey
from pytrat.server import (
    JwtAccessTokenValidator,
    JwtIssuer,
    OAuthError,
    SelfSignedValidator,
    SubjectTokenValidator,
    UnsignedJsonValidator,
    WorkloadRegistry,
)
from pytrat.server.workloads import WorkloadIdentity

IDP, API, TTS = "https://idp.example", "https://api.example", "https://tts.example/token"
IDP_KEY, GATEWAY_KEY = key("fuzz-idp"), key("fuzz-gw")
GATEWAY = WorkloadIdentity("api-gateway")
_CLOCK = clock()
_REGISTRY = WorkloadRegistry({GATEWAY.id: GATEWAY_KEY.key_set()})


@dataclass(frozen=True, slots=True)
class _Target:
    validator: SubjectTokenValidator
    signer: TestKey | None
    header: dict[str, object]
    payload: dict[str, object]
    requester_asserted: bool


_TARGETS = (
    _Target(
        JwtAccessTokenValidator(
            [JwtIssuer(IDP, IDP_KEY.key_set(), API, frozenset({"ES256"}))], clock=_CLOCK
        ),
        IDP_KEY,
        {"typ": "at+jwt", "alg": "ES256", "kid": IDP_KEY.kid},
        {
            "iss": IDP,
            "aud": API,
            "sub": "user:123",
            "scope": "payments.transfer",
            "iat": NOW,
            "exp": NOW + 600,
            "client_id": "web-app",
            "act": {"sub": "agent-1"},
        },
        requester_asserted=False,
    ),
    _Target(
        SelfSignedValidator(
            _REGISTRY,
            tts_identifiers=frozenset({TTS}),
            algorithms=frozenset({"ES256"}),
            clock=_CLOCK,
        ),
        GATEWAY_KEY,
        {"typ": "JWT", "alg": "ES256", "kid": GATEWAY_KEY.kid},
        {"iss": GATEWAY.id, "aud": TTS, "sub": "user:123", "iat": NOW, "exp": NOW + 60},
        requester_asserted=True,
    ),
    _Target(
        UnsignedJsonValidator(frozenset({GATEWAY.id}), clock=_CLOCK),
        None,
        {},
        {"sub": "user:123", "scope": "payments.read", "exp": NOW + 60},
        requester_asserted=True,
    ),
)


def _subject(target: _Target, mode: int, raw_header: bytes, raw_payload: bytes) -> str:
    if mode == 0:
        return text(raw_header)
    payload = overlay(target.payload, raw_payload)
    if target.signer is None:
        return text(payload)
    return sign_segments(overlay(target.header, raw_header), payload, target.signer)


def TestOneInput(data: bytes) -> None:  # noqa: N802 - name required by Atheris
    """Validate one subject token as the gateway workload."""
    target, rest = choose(data, _TARGETS)
    mode, rest = choose(rest, (0, 1))
    raw_header, raw_payload = split(rest, 2)
    raw_subject = _subject(target, mode, raw_header, raw_payload)
    if not raw_subject:
        return  # the form parser rejects an empty subject_token before any validator runs
    subject = SecretToken(raw_subject)
    try:
        info = target.validator.validate(subject, GATEWAY)
    except OAuthError as error:
        assert_no_token(error)
        return
    if not info.sub:
        raise AssertionError("accepted a subject without sub")
    if info.exp is not None and info.exp <= NOW:
        raise AssertionError("accepted an expired subject token")
    if target.requester_asserted and info.act is not None:
        raise AssertionError("a requester-asserted subject carried a delegated actor")


def seeds() -> Iterator[bytes]:
    """A valid subject for each validator and typical rejections."""
    for index, target in enumerate(_TARGETS):
        yield bytes([index, 1]) + join(b"{}", b"{}")
        yield bytes([index, 1]) + join(b"{}", b'{"sub": null}')
        yield bytes([index, 1]) + join(b"{}", b'{"exp": 1}')
        yield bytes([index, 1]) + join(b"{}", b'{"act": {"sub": "x"}}')
        yield bytes([index, 1]) + join(b'{"alg": "none"}', b"{}")
        yield bytes([index, 0]) + json.dumps(target.payload).encode()
    yield bytes([0, 1]) + join(b'{"kid": "fuzz-gw"}', b"{}")
    yield bytes([0, 1]) + join(b"{}", b'{"aud": ["https://api.example", "other"]}')
    yield bytes([1, 1]) + join(b"{}", b'{"iss": "someone-else"}')
    yield bytes([2, 1]) + join(b"", b'{"scope": 5}')
    yield bytes([0, 0])  # empty subject (rejected by the form parser, skipped here)


if __name__ == "__main__":
    fuzz(TestOneInput)
