"""Attack scenarios against token verification, written as the attacker would try them."""

from __future__ import annotations

import base64
import json
import logging

import pytest

from pytrat.core import (
    ReasonCode,
    StaticKeySet,
    TokenError,
    TokenVerifier,
    VerifierSettings,
)
from pytrat.core.testing import TokenFactory, b64url, generate_test_key

pytestmark = pytest.mark.security


@pytest.fixture
def factory() -> TokenFactory:
    return TokenFactory.create("ES256")


def rejected(verifier: TokenVerifier, token: str) -> ReasonCode:
    with pytest.raises(TokenError) as excinfo:
        verifier.verify(token)
    return excinfo.value.reason


def test_alg_none_with_fake_signature_is_rejected(factory: TokenFactory) -> None:
    head, body, _ = factory.unsigned().split(".")
    assert rejected(factory.verifier(), f"{head}.{body}.AAAA") is ReasonCode.ALGORITHM_NOT_ALLOWED


def test_rs256_public_key_used_as_hmac_secret_is_rejected() -> None:
    factory = TokenFactory.create("RS256")
    settings = VerifierSettings(trust_domain="payments.internal", algorithms=frozenset({"RS256"}))
    verifier = factory.verifier(settings)
    assert rejected(verifier, factory.hmac_with_public_key()) is ReasonCode.ALGORITHM_NOT_ALLOWED


def test_attacker_key_embedded_in_jwk_header_is_ignored(factory: TokenFactory) -> None:
    attacker = generate_test_key("ES256", kid=factory.key.kid)
    token = TokenFactory(key=attacker, clock=factory.clock).mint_payload(
        factory.claims(), jwk=attacker.jwk()
    )
    assert rejected(factory.verifier(), token) is ReasonCode.ALGORITHM_NOT_ALLOWED


def test_attacker_key_with_colliding_kid_fails_signature(factory: TokenFactory) -> None:
    attacker = generate_test_key("ES256", kid=factory.key.kid)
    token = TokenFactory(key=attacker, clock=factory.clock).mint()
    assert rejected(factory.verifier(), token) is ReasonCode.SIGNATURE_INVALID


@pytest.mark.parametrize("kid", ["../../etc/passwd", "' OR 1=1 --", "\x00", "a" * 5000])
def test_hostile_kid_values_resolve_to_no_key(factory: TokenFactory, kid: str) -> None:
    reason = rejected(factory.verifier(), factory.mint(headers={"kid": kid}))
    assert reason in {ReasonCode.KEY_UNKNOWN, ReasonCode.TOKEN_MALFORMED}


def test_token_for_another_trust_domain_is_not_accepted(factory: TokenFactory) -> None:
    """txn-tokens-11 §12.2: a token MUST NOT be accepted outside its Trust Domain."""
    token = factory.mint(aud="ledger.internal")
    assert rejected(factory.verifier(), token) is ReasonCode.TRUST_DOMAIN_MISMATCH


def test_aud_array_smuggling_both_domains_is_rejected(factory: TokenFactory) -> None:
    token = factory.mint(aud=["ledger.internal", "payments.internal"])
    assert rejected(factory.verifier(), token) is ReasonCode.CLAIM_INVALID


def test_duplicate_aud_parser_differential_is_rejected(factory: TokenFactory) -> None:
    body = json.dumps(factory.claims())[:-1] + ', "aud": "ledger.internal"}'
    token = factory.mint_payload(body.encode())
    assert rejected(factory.verifier(), token) is ReasonCode.TOKEN_MALFORMED


def test_payload_swapped_between_two_valid_tokens_fails_signature(factory: TokenFactory) -> None:
    small = factory.mint(tctx={"amount_minor": 100})
    large = factory.mint(tctx={"amount_minor": 900000})
    head, _, sig = small.split(".")
    swapped = f"{head}.{large.split('.')[1]}.{sig}"
    assert rejected(factory.verifier(), swapped) is ReasonCode.SIGNATURE_INVALID


def test_expired_token_replayed_later_is_rejected(factory: TokenFactory) -> None:
    token = factory.mint()
    factory.clock.advance(3600)
    assert rejected(factory.verifier(), token) is ReasonCode.TOKEN_EXPIRED


def test_long_lived_token_from_compromised_issuer_config_is_rejected(factory: TokenFactory) -> None:
    now = int(factory.clock.now())
    token = factory.mint(iat=now, exp=now + 86_400)
    assert rejected(factory.verifier(), token) is ReasonCode.LIFETIME_EXCEEDED


def test_jwe_shaped_token_is_rejected(factory: TokenFactory) -> None:
    header = b64url(json.dumps({"alg": "dir", "enc": "A256GCM", "typ": "txntoken+jwt"}).encode())
    assert rejected(factory.verifier(), f"{header}.a.b.c.d") is ReasonCode.TOKEN_MALFORMED


def test_huge_token_rejected_before_decoding(factory: TokenFactory) -> None:
    giant = "eyJ" + "A" * 1_000_000 + ".e30.sig"
    assert rejected(factory.verifier(), giant) is ReasonCode.TOKEN_MALFORMED


def test_rotated_out_key_no_longer_verifies(factory: TokenFactory) -> None:
    token = factory.mint()
    new_key = generate_test_key("ES256")
    verifier = TokenVerifier(
        factory.verifier().settings, StaticKeySet([new_key.verification_key]), factory.clock
    )
    assert rejected(verifier, token) is ReasonCode.KEY_UNKNOWN


def test_errors_and_logs_never_contain_the_token(
    factory: TokenFactory, caplog: pytest.LogCaptureFixture
) -> None:
    token = factory.mint(aud="elsewhere")
    with caplog.at_level(logging.DEBUG), pytest.raises(TokenError) as excinfo:
        factory.verifier().verify(token)
    rendered = f"{excinfo.value!s} {excinfo.value!r} {excinfo.value.detail}"
    for segment in token.split("."):
        assert segment not in rendered
    assert token not in caplog.text


def test_signature_from_header_only_cannot_be_reused() -> None:
    """Header confusion: a valid signature over a different header must not verify."""
    factory = TokenFactory.create("ES256")
    token = factory.mint()
    _, body, sig = token.split(".")
    other_header = (
        base64.urlsafe_b64encode(
            json.dumps(
                {"typ": "txntoken+jwt", "alg": "ES256", "kid": factory.key.kid, "x": 1}
            ).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    assert (
        rejected(factory.verifier(), f"{other_header}.{body}.{sig}") is ReasonCode.SIGNATURE_INVALID
    )
