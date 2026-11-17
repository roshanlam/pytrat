"""Conformance: Txn-Token format (txn-tokens-11 §9) and receiver validation (§12.2).

Driven by ``vectors/token_validation.json`` so other implementations can reuse the vectors.
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path

import pytest

from pytrat.core import ReasonCode, TokenError, TokenVerifier
from pytrat.core.crypto import sign_raw
from pytrat.core.testing import TokenFactory, b64url

VECTORS = json.loads((Path(__file__).parent / "vectors" / "token_validation.json").read_text())
_TIME = re.compile(r"<now(?: ([+-]) (\d+))?>")


def _resolve(value: object, now: int) -> object:
    if isinstance(value, str) and (match := _TIME.fullmatch(value)):
        sign, delta = match.groups()
        return now + (int(delta) if sign == "+" else -int(delta)) if sign else now
    return value


def _apply(base: dict, overrides: dict, now: int) -> dict:
    result = dict(base)
    for name, value in overrides.items():
        if value is None:
            result.pop(name, None)
        else:
            result[name] = _resolve(value, now)
    return result


def _mint(factory: TokenFactory, vector: dict) -> str:
    now = int(factory.clock.now())
    claims = _apply(factory.claims(txn="txn-9274"), vector.get("claims", {}), now)
    base_header = {"typ": "txntoken+jwt", "alg": factory.key.alg, "kid": factory.key.kid}
    header = _apply(base_header, vector.get("header", {}), now)
    signing_input = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(claims).encode())}"
    if header.get("alg") != factory.key.alg:
        # A relabelled algorithm must be refused on the allowlist before any key is selected,
        # so the signature content is irrelevant.
        return f"{signing_input}.c2lnbmF0dXJl"
    signature = sign_raw(signing_input.encode(), factory.key.private_key, factory.key.alg)
    return f"{signing_input}.{b64url(signature)}"


@pytest.mark.conformance("txn-tokens-11 §9, §12.2")
@pytest.mark.parametrize("vector", VECTORS["vectors"], ids=lambda v: f"§{v['section']}-{v['id']}")
def test_validation_vector(vector: dict) -> None:
    factory = TokenFactory.create("ES256")
    verifier: TokenVerifier = factory.verifier()
    token = _mint(factory, vector)
    if vector["expect"] == "accept":
        verified = verifier.verify(token)
        assert verified.claims.aud == "payments.internal"
        return
    with pytest.raises(TokenError) as excinfo:
        verifier.verify(token)
    assert excinfo.value.reason is ReasonCode(vector["expect"])


def test_every_required_claim_has_a_vector() -> None:
    """txn-tokens-11 §9.2: aud, txn, sub, scope, req_wl, iat and exp are REQUIRED."""
    required = {"aud", "txn", "sub", "scope", "req_wl", "iat", "exp"}
    covered = {
        v["id"].removeprefix("missing-")
        for v in VECTORS["vectors"]
        if v["id"].startswith("missing-")
    }
    assert required <= covered


def test_signed_payload_decodes_as_documented() -> None:
    """txn-tokens-11 §9.1: header carries typ txntoken+jwt and a kid (SHOULD)."""
    factory = TokenFactory.create("ES256")
    head = factory.mint().split(".")[0]
    header = json.loads(base64.urlsafe_b64decode(head + "=" * (-len(head) % 4)))
    assert header["typ"] == "txntoken+jwt"
    assert header["kid"] == factory.key.kid
