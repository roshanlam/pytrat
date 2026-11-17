from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from pytrat.core import (
    ConfigurationError,
    ReasonCode,
    StaticKeySet,
    TokenError,
    VerificationKey,
)
from pytrat.core.crypto import (
    algorithms_for_key,
    generate_private_key,
    load_private_key_pem,
    load_public_jwk,
    private_key_to_pem,
    public_jwk,
    sign_compact,
    sign_raw,
    verify_signature,
)
from pytrat.core.testing import generate_test_key


class TestStaticKeySet:
    def test_round_trip_through_jwks(self, tmp_path) -> None:
        keys = [generate_test_key(alg) for alg in ("ES256", "EdDSA", "PS256")]
        key_set = keys[0].key_set(*keys[1:])
        path = tmp_path / "jwks.json"
        path.write_text(key_set.to_json())
        loaded = StaticKeySet.from_jwks_file(path)
        assert loaded.kids == key_set.kids
        assert len(loaded) == 3
        for key in keys:
            found = loaded.get(key.kid)
            assert found is not None
            assert found.algorithms == frozenset({key.alg})
        assert "kids=" in repr(loaded)

    def test_lookup_without_kid(self) -> None:
        one = generate_test_key().key_set()
        two = generate_test_key().key_set(generate_test_key())
        assert one.get(None) is not None
        assert two.get(None) is None
        assert one.get("nope") is None

    def test_duplicate_kid(self) -> None:
        a = generate_test_key(kid="same")
        b = generate_test_key(kid="same")
        with pytest.raises(ConfigurationError):
            a.key_set(b)

    @pytest.mark.parametrize(
        "document",
        [
            {},
            {"keys": "nope"},
            {"keys": ["nope"]},
            {"keys": [{"kty": "EC"}]},  # no kid
        ],
    )
    def test_invalid_documents(self, document: dict[str, object]) -> None:
        with pytest.raises(ConfigurationError):
            StaticKeySet.from_jwks(document)

    @pytest.mark.parametrize("kty", [["EC"], {"EC": 1}, None, 1])
    def test_non_string_kty_is_a_configuration_error(self, kty: object) -> None:
        """Regression (fuzz/fuzz_jwks.py): an unhashable ``kty`` raised TypeError."""
        jwk = {**generate_test_key("ES256", kid="k").jwk(), "kty": kty}
        with pytest.raises(ConfigurationError) as excinfo:
            StaticKeySet.from_jwks({"keys": [jwk]})
        assert excinfo.value.reason is ReasonCode.KEY_UNKNOWN

    @pytest.mark.parametrize("data", [b"not json", b"[]", b"{" + b" " * 300_000 + b"}"])
    def test_invalid_bytes(self, data: bytes) -> None:
        with pytest.raises(ConfigurationError):
            StaticKeySet.from_jwks_bytes(data)

    def test_deeply_nested_document_is_a_configuration_error(self) -> None:
        """Regression (fuzz/fuzz_strict_json.py): RecursionError escaped the parser."""
        with pytest.raises(ConfigurationError) as excinfo:
            StaticKeySet.from_jwks_bytes(b"[" * 120_000 + b"]" * 120_000)
        assert excinfo.value.reason is ReasonCode.KEY_UNKNOWN

    def test_verification_key_repr_and_restriction(self) -> None:
        key = generate_test_key("PS256")
        vk = VerificationKey.from_public_key("k", key.public_key)
        assert "PS256" in repr(vk)
        assert "RS256" in repr(vk)
        with pytest.raises(ConfigurationError):
            VerificationKey.from_public_key("k", key.public_key, "ES256")


class TestJwkParsing:
    def jwk(self, alg: str = "ES256") -> dict[str, object]:
        return generate_test_key(alg).jwk()

    def test_symmetric_keys_rejected(self) -> None:
        with pytest.raises(ConfigurationError, match="symmetric"):
            load_public_jwk({"kty": "oct", "k": "c2VjcmV0", "kid": "x"})

    def test_private_material_rejected(self) -> None:
        with pytest.raises(ConfigurationError, match="private"):
            load_public_jwk({**self.jwk(), "d": "AAAA"})

    @pytest.mark.parametrize(
        "override",
        [
            {"use": "enc"},
            {"key_ops": ["encrypt"]},
            {"key_ops": "verify"},
            {"alg": "PS256"},
            {"alg": 1},
        ],
    )
    def test_usage_and_alg_constraints(self, override: dict[str, object]) -> None:
        with pytest.raises(ConfigurationError):
            load_public_jwk({**self.jwk(), **override})

    @pytest.mark.parametrize("jwk", [{"kty": "XYZ"}, {"kty": "EC", "crv": "P-256", "x": "!!"}, {}])
    def test_malformed(self, jwk: dict[str, object]) -> None:
        with pytest.raises(ConfigurationError):
            load_public_jwk(jwk)

    def test_weak_rsa_rejected(self) -> None:
        weak = rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key()  # noqa: S505 - deliberately weak
        jwk = public_jwk(weak, kid="weak", alg="RS256")
        with pytest.raises(ConfigurationError, match="2048"):
            load_public_jwk(jwk)

    def test_rsa_key_without_alg_allows_rsa_family_only(self) -> None:
        jwk = {k: v for k, v in self.jwk("PS256").items() if k != "alg"}
        _, algorithms = load_public_jwk(jwk)
        assert algorithms == frozenset({"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"})

    def test_unsupported_curve_has_no_algorithms(self) -> None:
        key = ec.generate_private_key(ec.SECP256K1()).public_key()
        assert algorithms_for_key(key) == frozenset()

    def test_export_requires_compatible_alg(self) -> None:
        with pytest.raises(ConfigurationError):
            public_jwk(generate_test_key().public_key, kid="k", alg="RS256")


class TestSigning:
    @pytest.mark.parametrize("alg", ["ES256", "ES384", "ES512", "EdDSA", "PS256", "RS256"])
    def test_sign_then_verify(self, alg: str) -> None:
        key = generate_private_key(alg, rsa_bits=2048)
        token = sign_compact({"a": 1}, key, alg=alg, kid="k")
        assert verify_signature(token, key.public_key(), alg) == {"a": 1}

    def test_sign_without_kid_and_with_extra_headers(self) -> None:
        key = generate_private_key("ES256")
        token = sign_compact(
            {"a": 1}, key, alg="ES256", kid=None, typ="JWT", extra_headers={"x": 1}
        )
        assert verify_signature(token, key.public_key(), "ES256") == {"a": 1}

    @pytest.mark.parametrize("alg", ["none", "HS256"])
    def test_forbidden_algorithms_cannot_sign_or_verify(self, alg: str) -> None:
        key = generate_private_key("ES256")
        with pytest.raises(ConfigurationError):
            sign_compact({}, key, alg=alg, kid=None)
        with pytest.raises(ConfigurationError):
            sign_raw(b"x", key, alg)
        with pytest.raises(TokenError):
            verify_signature("a.b.c", key.public_key(), alg)

    def test_incompatible_signing_key(self) -> None:
        with pytest.raises(ConfigurationError):
            sign_compact({}, generate_private_key("ES256"), alg="PS256", kid=None)

    def test_unsupported_generation(self) -> None:
        with pytest.raises(ConfigurationError):
            generate_private_key("HS256")

    def test_pem_round_trip(self) -> None:
        key = generate_private_key("EdDSA")
        loaded = load_private_key_pem(private_key_to_pem(key))
        assert private_key_to_pem(loaded) == private_key_to_pem(key)

    def test_bad_pem(self) -> None:
        with pytest.raises(ConfigurationError):
            load_private_key_pem(b"-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----\n")

    def test_verify_undecodable_token(self) -> None:
        key = generate_private_key("ES256")
        with pytest.raises(TokenError):
            verify_signature("!!.!!.!!", key.public_key(), "ES256")

    def test_payload_is_compact_and_sorted(self) -> None:
        key = generate_private_key("ES256")
        token = sign_compact({"b": 1, "a": 2}, key, alg="ES256", kid=None)
        import base64

        body = token.split(".")[1]
        decoded = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
        assert decoded == json.dumps({"a": 2, "b": 1}, separators=(",", ":")).encode()


class TestVerifyJws:
    def test_generic_jwt_with_custom_typ(self) -> None:
        from pytrat.core import ReasonCode, verify_jws

        key = generate_test_key("ES256")
        token = sign_compact(
            {"iss": "client"}, key.private_key, alg="ES256", kid=key.kid, typ="at+jwt"
        )
        result = verify_jws(
            token, key.key_set(), algorithms=frozenset({"ES256"}), allowed_typ=frozenset({"at+jwt"})
        )
        assert result.payload == {"iss": "client"}
        assert result.key.kid == key.kid
        assert (
            verify_jws(token, key.key_set(), algorithms=frozenset({"ES256"}), allowed_typ=None).alg
            == "ES256"
        )
        with pytest.raises(TokenError) as excinfo:
            verify_jws(token, key.key_set(), algorithms=frozenset({"ES256"}))
        assert excinfo.value.reason is ReasonCode.TOKEN_TYPE_INVALID

    def test_typ_check_skipped_still_rejects_forbidden_algorithms(self) -> None:
        from pytrat.core import ReasonCode, verify_jws
        from pytrat.core.testing import TokenFactory

        factory = TokenFactory.create()
        with pytest.raises(TokenError) as excinfo:
            verify_jws(
                factory.hmac_with_public_key(),
                factory.key.key_set(),
                algorithms=frozenset({"ES256"}),
                allowed_typ=None,
            )
        assert excinfo.value.reason is ReasonCode.ALGORITHM_NOT_ALLOWED
