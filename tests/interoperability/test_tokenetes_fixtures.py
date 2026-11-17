"""Tokenetes interoperability, fixture-based (always runs; no Tokenetes process needed).

Tokenetes token shapes come from ``vectors/tokenetes.json`` (each shape cites the Tokenetes source
it was reproduced from) and are re-signed here with freshly generated keys. The tests pin down
*exactly* how PyTraT's strict txn-tokens-11 verifier treats them. See ``docs/interop/tokenetes.md``.

Tokenetes implements an early revision of the draft (``typ: txn_token``, ``purp``, ``azd``; see the
compatibility document), so its tokens are expected to be rejected. PyTraT deliberately has no
compatibility mode; these tests document the gap rather than paper over it.
"""

from __future__ import annotations

import base64
import copy
import json
import os
import re
import uuid
from pathlib import Path

import pytest

from pytrat.core import (
    ReasonCode,
    StaticKeySet,
    TokenError,
    TokenVerifier,
    VerifierSettings,
)
from pytrat.core.constants import DEFAULT_ALGORITHMS, TXN_TOKEN_TYP
from pytrat.core.crypto import peek_header
from pytrat.core.testing import FrozenClock, TestKey, TokenFactory, generate_test_key
from pytrat.server import KeyRingSigner, SigningKey

pytestmark = pytest.mark.integration

VECTORS = json.loads((Path(__file__).parent / "vectors" / "tokenetes.json").read_text())
NOW = 1_795_000_000
TOKENETES_ISSUER = VECTORS["token"]["claims"]["iss"]
TOKENETES_AUDIENCE = VECTORS["token"]["claims"]["aud"]
_TIME = re.compile(r"<now(?: \+ (\d+))?>")


def _tokenetes_kid() -> str:
    # tokenetes keys.go: base64.StdEncoding of 16 random bytes, so '+', '/' and '=' can occur.
    return base64.b64encode(os.urandom(16)).decode()


def _resolve(value: object) -> object:
    if value == "<uuid>":
        return str(uuid.uuid4())
    if isinstance(value, str) and (match := _TIME.fullmatch(value)):
        return NOW + int(match.group(1) or 0)
    return value


def tokenetes_claims(**overrides: object) -> dict[str, object]:
    """The Tokenetes claim set; an override of ``None`` drops the claim."""
    claims = {name: _resolve(value) for name, value in VECTORS["token"]["claims"].items()}
    claims = copy.deepcopy(claims)
    for name, value in overrides.items():
        if value is None:
            claims.pop(name, None)
        else:
            claims[name] = value
    return claims


@pytest.fixture
def key() -> TestKey:
    return generate_test_key("RS256", kid=_tokenetes_kid())


@pytest.fixture
def factory(key: TestKey) -> TokenFactory:
    return TokenFactory(key=key, trust_domain=TOKENETES_AUDIENCE, clock=FrozenClock(NOW))


def tokenetes_token(factory: TokenFactory, *, typ: str = "txn_token", **overrides: object) -> str:
    """Sign a Tokenetes-shaped token exactly as tokenetes service.go would (RS256, typ, kid)."""
    return factory.mint_payload(tokenetes_claims(**overrides), typ=typ)


def verifier(
    factory: TokenFactory, *, algorithms: frozenset[str] = frozenset({"RS256"}), **settings: object
) -> TokenVerifier:
    return TokenVerifier(
        VerifierSettings(
            trust_domain=TOKENETES_AUDIENCE,
            algorithms=algorithms,
            expected_issuer=TOKENETES_ISSUER,
            **settings,
        ),
        factory.key.key_set(),
        clock=factory.clock,
    )


def reject(token: str, token_verifier: TokenVerifier) -> TokenError:
    with pytest.raises(TokenError) as excinfo:
        token_verifier.verify(token)
    return excinfo.value


# ------------------------------------------------------------------ Tokenetes -> PyTraT


def test_tokenetes_jwks_document_loads_as_trusted_keys(key: TestKey) -> None:
    """Tokenetes' JWK members (keys.go) are a plain RFC 7517 RSA key that PyTraT can trust."""
    members = VECTORS["jwks"]["key_members"]
    jwk = {name: value for name, value in {**key.jwk(), "use": "sig"}.items() if name in members}
    assert sorted(jwk) == members

    keys = StaticKeySet.from_jwks({"keys": [jwk]})

    trusted = keys.get(key.kid)
    assert trusted is not None
    assert "RS256" in trusted.algorithms


def test_tokenetes_token_as_issued_is_rejected_for_its_typ(factory: TokenFactory) -> None:
    """txn-tokens-11 §9.1: typ MUST be txntoken+jwt; Tokenetes sends the draft-00/-01 txn_token."""
    error = reject(tokenetes_token(factory), verifier(factory))

    assert error.reason is ReasonCode.TOKEN_TYPE_INVALID


def test_tokenetes_typ_is_rejected_before_algorithm_with_default_settings(
    factory: TokenFactory,
) -> None:
    """With PyTraT's default allowlist the header typ is still the first failed check."""
    error = reject(tokenetes_token(factory), verifier(factory, algorithms=DEFAULT_ALGORITHMS))

    assert error.reason is ReasonCode.TOKEN_TYPE_INVALID


def test_tokenetes_header_is_otherwise_acceptable(factory: TokenFactory) -> None:
    """Apart from typ, the header (RS256, base64 kid, no key-selecting params) passes the peek."""
    token = tokenetes_token(factory, typ=TXN_TOKEN_TYP)

    header = peek_header(token, max_bytes=16_384)

    assert header.alg == "RS256"
    assert header.kid == factory.key.kid


# Each step repairs one more Tokenetes/-11 difference and asserts the *next* failed check, so the
# full list of blockers is pinned in verifier order (header, then claims in model order).
LAYERS = [
    pytest.param(
        {"typ": "txn_token"},
        {},
        ReasonCode.TOKEN_TYPE_INVALID,
        None,
        id="as-issued:typ-txn_token",
    ),
    pytest.param(
        {"typ": TXN_TOKEN_TYP, "algorithms": DEFAULT_ALGORITHMS},
        {},
        ReasonCode.ALGORITHM_NOT_ALLOWED,
        None,
        id="typ-fixed:RS256-not-in-default-allowlist",
    ),
    pytest.param(
        {"typ": TXN_TOKEN_TYP},
        {},
        ReasonCode.CLAIM_INVALID,
        "sub",
        id="RS256-allowed:sub-is-a-subject-identifier-object",
    ),
    pytest.param(
        {"typ": TXN_TOKEN_TYP},
        {"sub": "alice@example.com"},
        ReasonCode.CLAIM_MISSING,
        "scope",
        id="sub-string:purp-is-not-scope",
    ),
    pytest.param(
        {"typ": TXN_TOKEN_TYP},
        {"sub": "alice@example.com", "scope": "stock-trade"},
        ReasonCode.CLAIM_MISSING,
        "req_wl",
        id="scope-added:req_wl-missing",
    ),
]


@pytest.mark.parametrize(("settings", "claims", "reason", "claim"), LAYERS)
def test_tokenetes_token_blockers_in_verifier_order(
    factory: TokenFactory,
    settings: dict[str, object],
    claims: dict[str, object],
    reason: ReasonCode,
    claim: str | None,
) -> None:
    """txn-tokens-11 §9.1 (typ), §9.2 (sub string, scope and req_wl REQUIRED), PyTraT profile P1."""
    options = dict(settings)
    typ = str(options.pop("typ"))
    token = tokenetes_token(factory, typ=typ, **claims)

    error = reject(token, verifier(factory, **options))

    assert error.reason is reason
    if claim is not None:
        assert f"'{claim}'" in error.detail


def test_fully_repaired_tokenetes_token_is_accepted_and_azd_is_ignored(
    factory: TokenFactory,
) -> None:
    """Only after every -11 difference is repaired does it verify; ``azd`` is an unknown claim.

    txn-tokens-11 §9.2: unknown claims are ignored, so the transaction details Tokenetes puts in
    ``azd`` are *not* available as ``tctx`` (renamed in draft -04).
    """
    token = tokenetes_token(
        factory, typ=TXN_TOKEN_TYP, sub="alice@example.com", scope="stock-trade", req_wl="gateway"
    )

    verified = verifier(factory).verify(token)

    assert verified.claims.aud == TOKENETES_AUDIENCE
    assert verified.claims.tctx is None
    assert verified.claims.rctx == {"req_ip": "203.0.113.7"}
    assert "azd" not in verified.claims.to_payload()
    assert "purp" not in verified.claims.to_payload()


def test_tokenetes_null_azd_is_ignored(factory: TokenFactory) -> None:
    """Tokenetes emits ``"azd": null`` for TraT rules without an azdMapping (rules.go)."""
    payload = tokenetes_claims(sub="alice@example.com", scope="stock-trade", req_wl="gateway")
    payload["azd"] = None
    null_azd = factory.mint_payload(payload, typ=TXN_TOKEN_TYP)

    assert verifier(factory).verify(null_azd).claims.tctx is None


def test_tokenetes_configurable_lifetime_above_pytrat_maximum_is_rejected(
    factory: TokenFactory,
) -> None:
    """Tokenetes lifeTime is free-form (e.g. "10m"); PyTraT profile P3 caps it at 300 s."""
    token = tokenetes_token(
        factory,
        typ=TXN_TOKEN_TYP,
        sub="alice@example.com",
        scope="stock-trade",
        req_wl="gateway",
        exp=NOW + 600,
    )

    error = reject(token, verifier(factory))

    assert error.reason is ReasonCode.LIFETIME_EXCEEDED


def test_tokenetes_audience_is_compared_exactly(factory: TokenFactory) -> None:
    """txn-tokens-11 §12.2: aud must equal the Trust Domain; a trailing '/' is a different value."""
    token = tokenetes_token(
        factory, typ=TXN_TOKEN_TYP, sub="alice@example.com", scope="stock-trade", req_wl="gateway"
    )
    without_slash = TOKENETES_AUDIENCE.rstrip("/")

    error = reject(
        token,
        TokenVerifier(
            VerifierSettings(trust_domain=without_slash, algorithms=frozenset({"RS256"})),
            factory.key.key_set(),
            clock=factory.clock,
        ),
    )

    assert error.reason is ReasonCode.TRUST_DOMAIN_MISMATCH


# ------------------------------------------------------------------ PyTraT -> Tokenetes
#
# tokenetes-agent cannot be run here; these tests pin the properties of PyTraT TTS output that the
# agent's verifier (tokenetes-agent trat.go / tratverifier.go) cannot accept. The live suite
# (test_tokenetes_live.py) shows the agent's actual responses.


def _pytrat_tts_token(alg: str) -> tuple[str, dict[str, object]]:
    signing = generate_test_key(alg, kid=f"pytrat-tts-{alg.lower()}")
    signer = KeyRingSigner([SigningKey(kid=signing.kid, alg=alg, private_key=signing.private_key)])
    claims = TokenFactory(key=signing, clock=FrozenClock(NOW)).claims()
    return signer.sign(claims), signer.jwks()


def _segment(token: str, index: int) -> dict[str, object]:
    raw = token.split(".")[index]
    decoded: dict[str, object] = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    return decoded


def test_pytrat_tts_default_algorithm_is_not_rsa() -> None:
    """tokenetes-agent only accepts *jwt.SigningMethodRSA; the PyTraT TTS defaults to ES256."""
    token, _ = _pytrat_tts_token("ES256")

    assert _segment(token, 0)["alg"] == "ES256"


def test_pytrat_tts_rs256_token_has_shape_tokenetes_agent_cannot_decode() -> None:
    """Even signed RS256, a -11 token has a string ``sub`` and ``scope`` instead of ``purp``.

    tokenetes-agent decodes ``sub`` into a {format, email} struct (decode error for a string) and
    matches its verification rules on ``purp``.
    """
    token, jwks = _pytrat_tts_token("RS256")
    header, claims = _segment(token, 0), _segment(token, 1)

    assert header["alg"] == "RS256"
    assert header["typ"] == TXN_TOKEN_TYP
    assert isinstance(claims["sub"], str)
    assert "purp" not in claims
    assert "azd" not in claims
    assert "scope" in claims
    assert "tctx" in claims
    keys = jwks["keys"]
    assert isinstance(keys, list)
    assert keys[0]["kty"] == "RSA"
