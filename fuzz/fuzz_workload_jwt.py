"""Fuzz resource-side workload authentication (``WorkloadJwtAuthenticator.authenticate``).

Input layout: ``signer byte || mode byte || header || NUL || payload || NUL || peer``.

* mode 0: ``header`` is the raw ``Workload-Identity`` header value.
* mode 1: header and payload are JSON overrides on a valid workload JWT, signed by ``signer``.
* mode 2: as mode 1, but the header is sent twice.

Invariants: only :class:`PyTraTError` is raised; an accepted credential authenticates exactly the
owner of the signing key; a repeated header is never accepted.
"""

from __future__ import annotations

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
from pytrat.core import InboundRequest, PyTraTError, WorkloadJwtAuthenticator, WorkloadKeys

AUDIENCE = "payment-service"
HEADER_NAME = "Workload-Identity"
_SIGNERS = (("api-gateway", key("fuzz-gw")), ("ledger", key("fuzz-ledger")))
_AUTHENTICATOR = WorkloadJwtAuthenticator(
    WorkloadKeys({owner: signer.key_set() for owner, signer in _SIGNERS}),
    audience=AUDIENCE,
    clock=clock(),
)


def TestOneInput(data: bytes) -> None:  # noqa: N802 - name required by Atheris
    """Authenticate one inbound request carrying a fuzzer-built workload JWT."""
    (owner, signer), rest = choose(data, _SIGNERS)
    mode, rest = choose(rest, (0, 1, 2))
    raw_header, raw_payload, raw_peer = split(rest, 3)
    if mode == 0:
        credential = text(raw_header)
    else:
        header = overlay({"typ": "wit+jwt", "alg": "ES256", "kid": signer.kid}, raw_header)
        valid = {"sub": owner, "aud": AUDIENCE, "iat": NOW, "exp": NOW + 60}
        credential = sign_segments(header, overlay(valid, raw_payload), signer)
    headers = [(HEADER_NAME, credential)] * (2 if mode == 2 else 1)
    try:
        identity = _AUTHENTICATOR.authenticate(InboundRequest(tuple(headers), text(raw_peer)))
    except PyTraTError as error:
        assert_no_token(error)
        return
    if identity is None:
        raise AssertionError("a present workload credential was treated as absent")
    if mode != 1 or identity.id != owner:
        raise AssertionError("authenticated a workload other than the signing key's owner")


def seeds() -> Iterator[bytes]:
    """A valid credential per workload and typical rejections."""
    for index in range(len(_SIGNERS)):
        yield bytes([index, 1]) + join(b"{}", b"{}", b"10.0.0.1")
    yield bytes([0, 2]) + join(b"{}", b"{}", b"")
    yield bytes([0, 1]) + join(b"{}", b'{"sub": "ledger"}', b"")
    yield bytes([0, 1]) + join(b"{}", b'{"iss": "ledger"}', b"")
    yield bytes([0, 1]) + join(b"{}", b'{"aud": ["payment-service", "x"]}', b"")
    yield bytes([0, 1]) + join(b"{}", b'{"exp": 1795000400}', b"")
    yield bytes([0, 1]) + join(b"{}", b'{"iat": true}', b"")
    yield bytes([0, 1]) + join(b'{"typ": "txntoken+jwt"}', b"{}", b"")
    yield bytes([0, 1]) + join(b'{"kid": "fuzz-ledger"}', b"{}", b"")
    yield bytes([0, 0]) + b"not-a-jwt"


if __name__ == "__main__":
    fuzz(TestOneInput)
