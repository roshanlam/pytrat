from __future__ import annotations

from datetime import timedelta

import pytest

from pytrat.core import (
    ConfigurationError,
    ReasonCode,
    StaticKeySet,
    TokenError,
    TokenVerifier,
    VerifiedToken,
    VerifierSettings,
)
from pytrat.core.testing import TokenFactory, b64url, generate_test_key


def reason(verifier: TokenVerifier, token: str) -> ReasonCode:
    with pytest.raises(TokenError) as excinfo:
        verifier.verify(token)
    return excinfo.value.reason


class TestAccepts:
    @pytest.mark.parametrize("alg", ["ES256", "ES384", "ES512", "EdDSA", "PS256", "RS256"])
    def test_valid_token_for_each_supported_algorithm(self, alg: str) -> None:
        factory = TokenFactory.create(alg)
        verified = factory.verifier().verify(factory.mint())
        assert verified.claims.aud == "payments.internal"
        assert verified.alg == alg
        assert verified.kid == factory.key.kid

    def test_exposes_claims_digest_and_forwardable(self, factory, verifier) -> None:
        raw = factory.mint(txn="txn-1")
        verified = verifier.verify(raw)
        assert verified.id == "txn-1"
        assert verified.forwardable.reveal() == raw
        assert verified.digest == verified.forwardable.digest
        assert raw not in repr(verified)

    def test_typ_with_application_prefix_and_mixed_case(self, factory, verifier) -> None:
        verifier.verify(factory.mint(headers={"typ": "application/TxnToken+JWT"}))

    def test_unknown_claims_are_ignored(self, factory, verifier) -> None:
        """txn-tokens-11 §9.2: recipients MUST ignore claims they do not understand."""
        verified = verifier.verify(factory.mint(future_claim={"x": 1}))
        assert not hasattr(verified.claims, "future_claim")

    def test_within_leeway_after_expiry(self, factory, verifier) -> None:
        raw = factory.mint()
        factory.clock.advance(factory.lifetime + 4)
        verifier.verify(raw)

    def test_kid_optional_when_configured_and_single_key(self, factory) -> None:
        settings = VerifierSettings(
            trust_domain="payments.internal", algorithms=frozenset({"ES256"}), require_kid=False
        )
        verifier = factory.verifier(settings)
        verifier.verify(factory.mint(headers={"kid": None}))

    def test_expected_issuer_matches(self, factory) -> None:
        settings = VerifierSettings(
            trust_domain="payments.internal",
            algorithms=frozenset({"ES256"}),
            expected_issuer="https://tts.test",
        )
        factory.verifier(settings).verify(factory.mint())


class TestRejectsShape:
    @pytest.mark.parametrize(
        "token",
        ["", "abc", "a.b", "a.b.c.d", "a.b.c.d.e", "a b.c.d", "a.b.c=", "eyJ.e30."],
    )
    def test_not_a_compact_jws(self, verifier, token: str) -> None:
        assert reason(verifier, token) is ReasonCode.TOKEN_MALFORMED

    def test_oversized_token(self, factory) -> None:
        settings = VerifierSettings(
            trust_domain="payments.internal", algorithms=frozenset({"ES256"}), max_token_bytes=512
        )
        token = factory.mint(padding="x" * 600)
        assert reason(factory.verifier(settings), token) is ReasonCode.TOKEN_MALFORMED

    def test_header_not_json(self, verifier) -> None:
        assert reason(verifier, f"{b64url(b'not json')}.e30.c2ln") is ReasonCode.TOKEN_MALFORMED

    def test_header_not_object(self, verifier) -> None:
        assert reason(verifier, f"{b64url(b'[1]')}.e30.c2ln") is ReasonCode.TOKEN_MALFORMED

    def test_header_duplicate_keys(self, verifier) -> None:
        header = b'{"typ":"txntoken+jwt","alg":"ES256","alg":"none"}'
        assert reason(verifier, f"{b64url(header)}.e30.c2ln") is ReasonCode.TOKEN_MALFORMED

    def test_stripped_signature(self, factory, verifier) -> None:
        head, body, _ = factory.mint().split(".")
        assert reason(verifier, f"{head}.{body}.") is ReasonCode.TOKEN_MALFORMED

    def test_payload_duplicate_claims(self, factory, verifier) -> None:
        payload = b'{"aud":"evil","aud":"payments.internal"}'
        assert reason(verifier, factory.mint_payload(payload)) is ReasonCode.TOKEN_MALFORMED

    def test_payload_not_json(self, factory, verifier) -> None:
        assert reason(verifier, factory.mint_payload(b"\xff\xfe")) is ReasonCode.TOKEN_MALFORMED

    def test_payload_not_object(self, factory, verifier) -> None:
        assert reason(verifier, factory.mint_payload(b"[1,2]")) is ReasonCode.TOKEN_MALFORMED

    def test_payload_nan(self, factory, verifier) -> None:
        assert reason(verifier, factory.mint_payload(b'{"iat":NaN}')) is ReasonCode.TOKEN_MALFORMED

    def test_empty_kid(self, factory, verifier) -> None:
        assert reason(verifier, factory.mint(headers={"kid": ""})) is ReasonCode.TOKEN_MALFORMED

    def test_missing_kid_when_required(self, factory, verifier) -> None:
        assert reason(verifier, factory.mint(headers={"kid": None})) is ReasonCode.TOKEN_MALFORMED


class TestRejectsHeader:
    @pytest.mark.parametrize("typ", ["JWT", "at+jwt", "txntoken", None, 7])
    def test_wrong_typ(self, factory, verifier, typ: object) -> None:
        """txn-tokens-11 §9.1: typ MUST be txntoken+jwt."""
        assert reason(verifier, factory.mint(headers={"typ": typ})) is ReasonCode.TOKEN_TYPE_INVALID

    def test_alg_none(self, factory, verifier) -> None:
        head, body, _ = factory.unsigned().split(".")
        token = f"{head}.{body}.c2ln"
        assert reason(verifier, token) is ReasonCode.ALGORITHM_NOT_ALLOWED

    def test_hmac_keyed_with_public_key(self, factory, verifier) -> None:
        assert reason(verifier, factory.hmac_with_public_key()) is ReasonCode.ALGORITHM_NOT_ALLOWED

    def test_supported_but_not_allowlisted_algorithm(self) -> None:
        factory = TokenFactory.create("RS256")
        settings = VerifierSettings(trust_domain="payments.internal")  # default excludes RS256
        verifier = TokenVerifier(settings, factory.key.key_set(), clock=factory.clock)
        assert reason(verifier, factory.mint()) is ReasonCode.ALGORITHM_NOT_ALLOWED

    @pytest.mark.parametrize("param", ["jwk", "jku", "x5u", "x5c", "crit", "b64"])
    def test_key_selecting_or_extension_headers(self, factory, verifier, param: str) -> None:
        token = factory.mint_payload(factory.claims(), **{param: "https://attacker.example/k"})
        assert reason(verifier, token) is ReasonCode.ALGORITHM_NOT_ALLOWED


class TestRejectsKeyAndSignature:
    def test_unknown_kid(self, factory, verifier) -> None:
        assert reason(verifier, factory.mint(headers={"kid": "other"})) is ReasonCode.KEY_UNKNOWN

    def test_signed_by_untrusted_key_with_trusted_kid(self, factory, verifier) -> None:
        attacker = generate_test_key("ES256", kid=factory.key.kid)
        assert reason(verifier, factory.mint(key=attacker)) is ReasonCode.SIGNATURE_INVALID

    def test_tampered_payload(self, factory, verifier) -> None:
        head, _, sig = factory.mint().split(".")
        forged_body = b64url(b'{"aud":"payments.internal"}')
        assert reason(verifier, f"{head}.{forged_body}.{sig}") is ReasonCode.SIGNATURE_INVALID

    def test_algorithm_not_bound_to_key_type(self) -> None:
        """An RSA token whose kid points at an EC key is rejected before signature checks."""
        rsa = TokenFactory.create("PS256")
        ec = generate_test_key("ES256", kid=rsa.key.kid)
        settings = VerifierSettings(
            trust_domain="payments.internal", algorithms=frozenset({"PS256", "ES256"})
        )
        verifier = TokenVerifier(settings, ec.key_set(), clock=rsa.clock)
        assert reason(verifier, rsa.mint()) is ReasonCode.ALGORITHM_NOT_ALLOWED

    def test_key_restricted_to_one_algorithm(self) -> None:
        factory = TokenFactory.create("RS256")
        restricted = generate_test_key("PS256", kid=factory.key.kid)
        keys = StaticKeySet([restricted.verification_key])
        settings = VerifierSettings(
            trust_domain="payments.internal", algorithms=frozenset({"RS256", "PS256"})
        )
        verifier = TokenVerifier(settings, keys, clock=factory.clock)
        assert reason(verifier, factory.mint()) is ReasonCode.ALGORITHM_NOT_ALLOWED


class TestRejectsClaims:
    @pytest.mark.parametrize("claim", ["aud", "txn", "sub", "scope", "req_wl", "iat", "exp"])
    def test_missing_required_claim(self, factory, verifier, claim: str) -> None:
        """txn-tokens-11 §9.2 required claims."""
        token = factory.mint(**{claim: None})
        assert reason(verifier, token) is ReasonCode.CLAIM_MISSING

    @pytest.mark.parametrize(
        ("claim", "value"),
        [
            ("aud", ["payments.internal"]),
            ("aud", ""),
            ("txn", 123),
            ("sub", ""),
            ("scope", ""),
            ("scope", "a  b"),
            ("scope", ["payments.transfer"]),
            ("scope", 'bad"scope'),
            ("req_wl", ["api-gateway"]),
            ("iat", "1795000000"),
            ("iat", 1795000000.5),
            ("iat", True),
            ("exp", -1),
            ("tctx", ["not", "an", "object"]),
            ("rctx", "string"),
            ("iss", 42),
            ("agentic_ctx", {"originator": {"id": "a"}}),
        ],
    )
    def test_invalid_claim_value(self, factory, verifier, claim: str, value: object) -> None:
        assert reason(verifier, factory.mint(**{claim: value})) is ReasonCode.CLAIM_INVALID

    def test_invalid_claim_detail_names_claim_not_value(self, factory, verifier) -> None:
        with pytest.raises(TokenError) as excinfo:
            verifier.verify(factory.mint(sub="", tctx={"secret": "s3cr3t"}))
        assert "sub" in excinfo.value.detail
        assert "s3cr3t" not in str(excinfo.value)

    def test_wrong_trust_domain(self, factory, verifier) -> None:
        """txn-tokens-11 §12.2: aud MUST identify the recipient's Trust Domain."""
        token = factory.mint(aud="ledger.internal")
        assert reason(verifier, token) is ReasonCode.TRUST_DOMAIN_MISMATCH

    def test_issuer_mismatch_and_missing(self, factory) -> None:
        settings = VerifierSettings(
            trust_domain="payments.internal",
            algorithms=frozenset({"ES256"}),
            expected_issuer="https://tts.internal",
        )
        verifier = factory.verifier(settings)
        assert reason(verifier, factory.mint()) is ReasonCode.ISSUER_MISMATCH
        assert reason(verifier, factory.mint(iss=None)) is ReasonCode.ISSUER_MISMATCH


class TestRejectsTime:
    def test_expired(self, factory, verifier) -> None:
        """txn-tokens-11 §12.2: the token MUST NOT be expired."""
        token = factory.mint()
        factory.clock.advance(factory.lifetime + 5)
        assert reason(verifier, token) is ReasonCode.TOKEN_EXPIRED

    def test_issued_in_the_future(self, factory, verifier) -> None:
        now = int(factory.clock.now())
        token = factory.mint(iat=now + 30, exp=now + 90)
        assert reason(verifier, token) is ReasonCode.TOKEN_NOT_YET_VALID

    def test_exp_not_after_iat(self, factory, verifier) -> None:
        now = int(factory.clock.now())
        assert reason(verifier, factory.mint(iat=now, exp=now)) is ReasonCode.CLAIM_INVALID

    def test_lifetime_exceeds_maximum(self, factory, verifier) -> None:
        now = int(factory.clock.now())
        token = factory.mint(iat=now, exp=now + 301)
        assert reason(verifier, token) is ReasonCode.LIFETIME_EXCEEDED


class TestCheckOrder:
    def test_header_checked_before_key(self, factory, verifier) -> None:
        token = factory.mint(headers={"typ": "JWT", "kid": "unknown"})
        assert reason(verifier, token) is ReasonCode.TOKEN_TYPE_INVALID

    def test_signature_checked_before_claims(self, factory, verifier) -> None:
        attacker = generate_test_key("ES256", kid=factory.key.kid)
        token = factory.mint(key=attacker, aud="elsewhere", sub=None)
        assert reason(verifier, token) is ReasonCode.SIGNATURE_INVALID

    def test_trust_domain_checked_before_time(self, factory, verifier) -> None:
        token = factory.mint(aud="elsewhere")
        factory.clock.advance(3600)
        assert reason(verifier, token) is ReasonCode.TRUST_DOMAIN_MISMATCH


class TestSettings:
    @pytest.mark.parametrize(
        "kwargs",
        [
            {"trust_domain": ""},
            {"algorithms": frozenset()},
            {"algorithms": frozenset({"none"})},
            {"algorithms": frozenset({"HS256", "ES256"})},
            {"algorithms": frozenset({"ES256K"})},
            {"max_lifetime": timedelta(0)},
            {"leeway": timedelta(seconds=61)},
            {"leeway": timedelta(seconds=-1)},
            {"max_token_bytes": 10},
            {"cache_size": -1},
        ],
    )
    def test_invalid_settings_rejected_at_construction(self, kwargs: dict[str, object]) -> None:
        base: dict[str, object] = {"trust_domain": "payments.internal", **kwargs}
        with pytest.raises(ConfigurationError):
            VerifierSettings(**base)  # type: ignore[arg-type]

    def test_verified_token_cannot_be_forged(self, factory, verifier) -> None:
        real = verifier.verify(factory.mint())
        with pytest.raises(TypeError):
            VerifiedToken(claims=real.claims, forwardable=real.forwardable, kid="k", alg="ES256")


class TestCache:
    @pytest.fixture
    def cached(self, factory: TokenFactory) -> TokenVerifier:
        settings = VerifierSettings(
            trust_domain="payments.internal", algorithms=frozenset({"ES256"}), cache_size=2
        )
        return factory.verifier(settings)

    def test_hit_returns_same_object(self, factory, cached) -> None:
        token = factory.mint()
        assert cached.verify(token) is cached.verify(token)

    def test_hit_still_enforces_expiry(self, factory, cached) -> None:
        token = factory.mint()
        cached.verify(token)
        factory.clock.advance(3600)
        assert reason(cached, token) is ReasonCode.TOKEN_EXPIRED
        assert reason(cached, token) is ReasonCode.TOKEN_EXPIRED

    def test_eviction_is_bounded(self, factory, cached) -> None:
        tokens = [factory.mint() for _ in range(3)]
        first = cached.verify(tokens[0])
        for token in tokens[1:]:
            cached.verify(token)
        assert cached.verify(tokens[0]) is not first

    def test_hit_invalidated_when_key_removed(self, factory) -> None:
        class Swappable:
            def __init__(self) -> None:
                self.keys = factory.key.key_set()

            def get(self, kid):
                return self.keys.get(kid)

        provider = Swappable()
        settings = VerifierSettings(
            trust_domain="payments.internal", algorithms=frozenset({"ES256"}), cache_size=4
        )
        verifier = TokenVerifier(settings, provider, clock=factory.clock)
        token = factory.mint()
        verifier.verify(token)
        provider.keys = StaticKeySet([])
        assert reason(verifier, token) is ReasonCode.KEY_UNKNOWN

    def test_malformed_tokens_never_reach_cache(self, cached) -> None:
        assert reason(cached, "x" * 20_000) is ReasonCode.TOKEN_MALFORMED
