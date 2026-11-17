"""Fuzz JWKS parsing: ``StaticKeySet.from_jwks_bytes`` and the refresher's ``parse_jwks``.

Invariants: only :class:`ConfigurationError` is raised, and an accepted set contains only public
asymmetric keys whose algorithms are supported and never ``none`` or ``HS*``.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

from fuzz._harness import fuzz, key
from pytrat.client import parse_jwks
from pytrat.core import ConfigurationError, StaticKeySet
from pytrat.core.constants import FORBIDDEN_ALGORITHMS, SUPPORTED_ALGORITHMS

_PRIVATE_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})


def _check_accepted(keys: StaticKeySet) -> None:
    for kid in keys.kids:
        verification_key = keys.get(kid)
        if verification_key is None:
            raise AssertionError("a listed kid does not resolve")
        algorithms = verification_key.algorithms
        if not algorithms or algorithms & FORBIDDEN_ALGORITHMS or algorithms - SUPPORTED_ALGORITHMS:
            raise AssertionError("an accepted key allows a forbidden or unsupported algorithm")
        if _PRIVATE_MEMBERS.intersection(verification_key.to_jwk()):
            raise AssertionError("an accepted key carries private or symmetric material")


def TestOneInput(data: bytes) -> None:  # noqa: N802 - name required by Atheris
    """Parse ``data`` as a JWKS document with both entry points."""
    for parse in (StaticKeySet.from_jwks_bytes, parse_jwks):
        try:
            keys = parse(data)
        except ConfigurationError:
            continue
        _check_accepted(keys)


def seeds() -> Iterator[bytes]:
    """Public keys of every supported type (generated now), plus invalid documents."""
    jwks = [key(f"seed-{alg.lower()}", alg).jwk() for alg in ("ES256", "ES384", "EdDSA", "RS256")]
    yield json.dumps({"keys": jwks}).encode()
    yield json.dumps({"keys": [jwks[0], jwks[0]]}).encode()
    yield json.dumps({"keys": [{**jwks[0], "alg": "HS256"}]}).encode()
    yield json.dumps({"keys": [{**jwks[0], "use": "enc"}]}).encode()
    yield json.dumps({"keys": [{**jwks[0], "d": "AAAA"}]}).encode()
    yield json.dumps({"keys": [{"kty": "oct", "kid": "s", "k": "AAAA"}]}).encode()
    yield json.dumps({"keys": [{"kty": "RSA", "kid": "weak", "n": "AQAB", "e": "AQAB"}]}).encode()
    # Regression (Atheris): an unhashable kty raised TypeError.
    yield json.dumps({"keys": [{**jwks[0], "kty": ["EC"]}]}).encode()
    yield b'{"keys": []}'
    yield b'{"keys": {}}'
    yield b"[]"


if __name__ == "__main__":
    fuzz(TestOneInput)
