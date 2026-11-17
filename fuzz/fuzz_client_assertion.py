"""Fuzz RFC 7523 client-assertion authentication at the TTS (``PrivateKeyJwtAuthenticator``).

Input layout: ``signer byte || mode byte || header || NUL || payload || NUL || client_id``.

* signer: which registered workload's key signs (mode 1).
* mode 0: ``header`` is the raw ``client_assertion``.
* mode 1: header and payload are JSON overrides on a valid assertion, signed by ``signer``.

Invariants: only :class:`OAuthError` is raised; an accepted assertion authenticates exactly the
workload that owns the signing key, and replaying it is refused with ``REPLAY_DETECTED``.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

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
from pytrat.core import InMemoryReplayStore, ReasonCode, Scope, SecretToken
from pytrat.core.constants import (
    CLIENT_ASSERTION_TYPE_JWT_BEARER,
    GRANT_TYPE_TOKEN_EXCHANGE,
    TOKEN_TYPE_ACCESS_TOKEN,
    TOKEN_TYPE_TXN_TOKEN,
)
from pytrat.server import ClientAuthParams, OAuthError, TokenRequest, WorkloadRegistry
from pytrat.server.workloads import PrivateKeyJwtAuthenticator

TOKEN_ENDPOINT = "https://tts.example/token"
_CLOCK = clock()
_SIGNERS = (("api-gateway", key("fuzz-gw")), ("payment-service", key("fuzz-pay")))
_REGISTRY = WorkloadRegistry({owner: signer.key_set() for owner, signer in _SIGNERS})


def _authenticator() -> PrivateKeyJwtAuthenticator:
    # A fresh replay store per input keeps every run deterministic.
    return PrivateKeyJwtAuthenticator(
        _REGISTRY,
        token_endpoint=TOKEN_ENDPOINT,
        algorithms=frozenset({"ES256"}),
        replay_store=InMemoryReplayStore(clock=_CLOCK),
        clock=_CLOCK,
    )


def _request(assertion: str, client_id: str) -> TokenRequest:
    return TokenRequest(
        grant_type=GRANT_TYPE_TOKEN_EXCHANGE,
        requested_token_type=TOKEN_TYPE_TXN_TOKEN,
        audience="payments.internal",
        scope=Scope.parse("payments.read"),
        subject_token=SecretToken("subject"),
        subject_token_type=TOKEN_TYPE_ACCESS_TOKEN,
        client=ClientAuthParams(
            client_id=client_id or None,
            client_assertion_type=CLIENT_ASSERTION_TYPE_JWT_BEARER,
            client_assertion=SecretToken(assertion) if assertion else None,
        ),
    )


def TestOneInput(data: bytes) -> None:  # noqa: N802 - name required by Atheris
    """Authenticate one fuzzer-built client assertion, then replay it."""
    (owner, signer), rest = choose(data, _SIGNERS)
    mode, rest = choose(rest, (0, 1))
    raw_header, raw_payload, raw_client_id = split(rest, 3)
    if mode == 0:
        assertion = text(raw_header)
    else:
        header = overlay({"alg": "ES256", "kid": signer.kid}, raw_header)
        valid = {"iss": owner, "sub": owner, "aud": TOKEN_ENDPOINT, "exp": NOW + 60, "jti": "j"}
        assertion = sign_segments(header, overlay(valid, raw_payload), signer)
    request = _request(assertion, text(raw_client_id))
    authenticator = _authenticator()
    try:
        identity = authenticator.authenticate(request, {}, None)
    except OAuthError as error:
        assert_no_token(error)
        return
    if mode == 0 or identity.id != owner:
        raise AssertionError("authenticated a workload other than the signing key's owner")
    try:
        authenticator.authenticate(request, {}, None)
    except OAuthError as error:
        if error.reason is not ReasonCode.REPLAY_DETECTED:
            raise AssertionError("a replayed assertion was refused for the wrong reason") from None
        return
    raise AssertionError("a replayed client assertion was accepted")


def seeds() -> Iterator[bytes]:
    """A valid assertion per workload and typical rejections."""
    for index in range(len(_SIGNERS)):
        yield bytes([index, 1]) + join(b"{}", b"{}", b"")
    yield bytes([0, 1]) + join(b"{}", b"{}", b"api-gateway")
    yield bytes([0, 1]) + join(b"{}", b"{}", b"payment-service")
    yield bytes([0, 1]) + join(b"{}", b'{"iss": "payment-service", "sub": "payment-service"}', b"")
    yield bytes([0, 1]) + join(b"{}", b'{"aud": ["https://tts.example/token"]}', b"")
    yield bytes([0, 1]) + join(b"{}", b'{"exp": 1795000400}', b"")
    yield bytes([0, 1]) + join(b"{}", b'{"jti": null}', b"")
    yield bytes([0, 1]) + join(b"{}", b'{"nbf": 1795000100}', b"")
    yield bytes([0, 1]) + join(b'{"kid": "fuzz-pay"}', b"{}", b"")
    yield bytes([0, 1]) + join(b'{"alg": "HS256"}', b"{}", b"")
    yield bytes([0, 0]) + json.dumps({"alg": "none"}).encode()


if __name__ == "__main__":
    fuzz(TestOneInput)
