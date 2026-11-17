"""JOSE primitives. The only module in PyTraT that imports ``jwt``.

Everything here is a thin, strict wrapper around PyJWT and ``cryptography``. Claim validation is
deliberately *not* delegated to PyJWT: PyTraT owns every claim check so that each one maps to a
specific :class:`~pytrat.core.errors.ReasonCode` and spec section.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, cast

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from jwt.algorithms import ECAlgorithm, OKPAlgorithm, RSAAlgorithm
from jwt.api_jws import PyJWS

from pytrat.core._json import DuplicateKeyError, compact_dumps, strict_loads
from pytrat.core.constants import (
    FORBIDDEN_ALGORITHMS,
    FORBIDDEN_HEADER_PARAMETERS,
    SUPPORTED_ALGORITHMS,
    TXN_TOKEN_TYP,
)
from pytrat.core.errors import ConfigurationError, ReasonCode, TokenError

type PublicKey = (
    rsa.RSAPublicKey | ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey | ed448.Ed448PublicKey
)
type PrivateKey = (
    rsa.RSAPrivateKey
    | ec.EllipticCurvePrivateKey
    | ed25519.Ed25519PrivateKey
    | ed448.Ed448PrivateKey
)

_SEGMENT: Final = re.compile(r"[A-Za-z0-9_-]+")
_RSA_ALGORITHMS: Final = frozenset({"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"})
_EC_CURVE_ALGORITHM: Final = {"secp256r1": "ES256", "secp384r1": "ES384", "secp521r1": "ES512"}
_MIN_RSA_BITS: Final = 2048
_PRIVATE_JWK_MEMBERS: Final = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
_JWS = PyJWS(options={"verify_signature": True})


@dataclass(frozen=True, slots=True)
class UnverifiedHeader:
    """The parts of an unverified JOSE header PyTraT is willing to read before verification.

    Only ``alg`` and ``kid`` are used, and only to select a *trusted* key and algorithm.
    """

    alg: str
    kid: str | None


def _b64url_decode(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded)


def _normalise_typ(typ: str) -> str:
    # RFC 7515 §4.1.9: media type names are case-insensitive and "application/" may be omitted.
    lowered = typ.lower()
    return lowered.removeprefix("application/")


def peek_header(raw_token: str, *, max_bytes: int) -> UnverifiedHeader:
    """Check token shape and the JOSE header without verifying the signature.

    This is the only function in PyTraT that reads an unverified token, and it returns only
    ``alg`` and ``kid``.

    Raises:
        TokenError: ``TOKEN_MALFORMED`` for anything that is not a compact JWS of acceptable size,
            ``TOKEN_TYPE_INVALID`` for a wrong ``typ``, ``ALGORITHM_NOT_ALLOWED`` for a forbidden
            algorithm or a key-selecting header parameter.
    """
    if not raw_token:
        raise TokenError(ReasonCode.TOKEN_MALFORMED, "token is empty")
    if len(raw_token) > max_bytes:
        raise TokenError(ReasonCode.TOKEN_MALFORMED, "token exceeds the maximum size")
    segments = raw_token.split(".")
    if len(segments) != 3:
        raise TokenError(ReasonCode.TOKEN_MALFORMED, "token is not a compact JWS")
    if not all(_SEGMENT.fullmatch(segment) for segment in segments):
        # Also rejects an empty (stripped) signature segment.
        raise TokenError(ReasonCode.TOKEN_MALFORMED, "token segments are not base64url")
    try:
        header = strict_loads(_b64url_decode(segments[0]))
    except (ValueError, binascii.Error, UnicodeDecodeError):
        raise TokenError(ReasonCode.TOKEN_MALFORMED, "token header is not valid JSON") from None
    if not isinstance(header, Mapping):
        raise TokenError(ReasonCode.TOKEN_MALFORMED, "token header is not a JSON object")
    return _check_header(cast("Mapping[str, object]", header))


def _check_header(header: Mapping[str, object]) -> UnverifiedHeader:
    typ = header.get("typ")
    # txn-tokens-11 §9.1: typ MUST be present and MUST be txntoken+jwt.
    if not isinstance(typ, str) or _normalise_typ(typ) != TXN_TOKEN_TYP:
        raise TokenError(ReasonCode.TOKEN_TYPE_INVALID, "header typ is not txntoken+jwt")
    alg = header.get("alg")
    if not isinstance(alg, str) or alg in FORBIDDEN_ALGORITHMS or alg not in SUPPORTED_ALGORITHMS:
        raise TokenError(ReasonCode.ALGORITHM_NOT_ALLOWED, "header alg is not permitted")
    # PyTraT profile: the token never chooses its own key or processing rules.
    if FORBIDDEN_HEADER_PARAMETERS.intersection(header):
        raise TokenError(ReasonCode.ALGORITHM_NOT_ALLOWED, "header contains a forbidden parameter")
    kid = header.get("kid")
    if kid is not None and (not isinstance(kid, str) or not kid):
        raise TokenError(ReasonCode.TOKEN_MALFORMED, "header kid must be a non-empty string")
    return UnverifiedHeader(alg=alg, kid=kid)


def verify_signature(raw_token: str, public_key: PublicKey, algorithm: str) -> Mapping[str, object]:
    """Verify a compact JWS with a trusted key and return the decoded payload object.

    The caller has already chosen ``algorithm`` from its allowlist and checked it is compatible
    with ``public_key``.

    Raises:
        TokenError: ``SIGNATURE_INVALID`` if verification fails, ``TOKEN_MALFORMED`` if the
            payload is not a strict JSON object.
    """
    if algorithm in FORBIDDEN_ALGORITHMS:  # defence in depth; callers never pass these
        raise TokenError(ReasonCode.ALGORITHM_NOT_ALLOWED, "algorithm is not permitted")
    try:
        decoded = _JWS.decode_complete(raw_token, key=public_key, algorithms=[algorithm])
    except jwt.InvalidSignatureError:
        raise TokenError(ReasonCode.SIGNATURE_INVALID, "signature verification failed") from None
    except jwt.InvalidAlgorithmError:
        raise TokenError(ReasonCode.ALGORITHM_NOT_ALLOWED, "algorithm is not permitted") from None
    except jwt.PyJWTError:
        raise TokenError(ReasonCode.TOKEN_MALFORMED, "token could not be decoded") from None
    try:
        payload = strict_loads(decoded["payload"])
    except DuplicateKeyError:
        raise TokenError(ReasonCode.TOKEN_MALFORMED, "payload contains duplicate claims") from None
    except (ValueError, UnicodeDecodeError):
        raise TokenError(ReasonCode.TOKEN_MALFORMED, "payload is not valid JSON") from None
    if not isinstance(payload, Mapping):
        raise TokenError(ReasonCode.TOKEN_MALFORMED, "payload is not a JSON object")
    return cast("Mapping[str, object]", payload)


def algorithms_for_key(public_key: PublicKey) -> frozenset[str]:
    """Return the JWS algorithms a key type can legitimately verify.

    Binding algorithms to key types means an EC or RSA key can never be used with any other family
    (key-confusion defence in depth on top of the allowlist).
    """
    if isinstance(public_key, rsa.RSAPublicKey):
        return _RSA_ALGORITHMS
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        alg = _EC_CURVE_ALGORITHM.get(public_key.curve.name)
        return frozenset({alg}) if alg else frozenset()
    return frozenset({"EdDSA"})


def load_public_jwk(jwk: Mapping[str, object]) -> tuple[PublicKey, frozenset[str]]:
    """Parse a public JWK into a key object and the algorithms it may verify.

    Raises:
        ConfigurationError: If the JWK is private, symmetric, weak, malformed or not for signing.
    """
    kty = jwk.get("kty")
    if kty == "oct":
        raise ConfigurationError("symmetric (oct) keys are not accepted", ReasonCode.KEY_UNKNOWN)
    if _PRIVATE_JWK_MEMBERS.intersection(jwk):
        raise ConfigurationError("JWK contains private key material", ReasonCode.KEY_UNKNOWN)
    use = jwk.get("use")
    if use is not None and use != "sig":
        raise ConfigurationError("JWK 'use' must be 'sig'", ReasonCode.KEY_UNKNOWN)
    key_ops = jwk.get("key_ops")
    if key_ops is not None and (not isinstance(key_ops, list) or "verify" not in key_ops):
        raise ConfigurationError("JWK 'key_ops' must include 'verify'", ReasonCode.KEY_UNKNOWN)
    if kty not in {"RSA", "EC", "OKP"}:
        raise ConfigurationError("unsupported JWK key type", ReasonCode.KEY_UNKNOWN)
    try:
        key = _key_from_jwk(kty, dict(jwk))
    except (jwt.PyJWTError, ValueError, TypeError, KeyError):
        raise ConfigurationError("JWK could not be parsed", ReasonCode.KEY_UNKNOWN) from None
    if not isinstance(
        key,
        rsa.RSAPublicKey
        | ec.EllipticCurvePublicKey
        | ed25519.Ed25519PublicKey
        | ed448.Ed448PublicKey,
    ):
        raise ConfigurationError("JWK is not a public signing key", ReasonCode.KEY_UNKNOWN)
    if isinstance(key, rsa.RSAPublicKey) and key.key_size < _MIN_RSA_BITS:
        raise ConfigurationError("RSA keys must be at least 2048 bits", ReasonCode.KEY_UNKNOWN)
    algorithms = algorithms_for_key(key)
    declared = jwk.get("alg")
    if declared is not None:
        if not isinstance(declared, str) or declared not in algorithms:
            raise ConfigurationError(
                "JWK 'alg' is incompatible with its key", ReasonCode.KEY_UNKNOWN
            )
        algorithms = frozenset({declared})
    return key, algorithms - FORBIDDEN_ALGORITHMS


def _key_from_jwk(kty: str, jwk: dict[str, object]) -> object:
    if kty == "RSA":
        return RSAAlgorithm.from_jwk(jwk)
    if kty == "EC":
        return ECAlgorithm.from_jwk(jwk)
    return OKPAlgorithm.from_jwk(jwk)


def public_jwk(public_key: PublicKey, *, kid: str, alg: str) -> dict[str, object]:
    """Export a public key as a JWK suitable for publishing in a JWKS."""
    if alg not in algorithms_for_key(public_key):
        raise ConfigurationError("algorithm is incompatible with the key", ReasonCode.KEY_UNKNOWN)
    jwk: dict[str, object]
    if isinstance(public_key, rsa.RSAPublicKey):
        jwk = RSAAlgorithm.to_jwk(public_key, as_dict=True)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        jwk = ECAlgorithm.to_jwk(public_key, as_dict=True)
    else:
        jwk = OKPAlgorithm.to_jwk(public_key, as_dict=True)
    return {**jwk, "kid": kid, "alg": alg, "use": "sig"}


def public_key_of(private_key: PrivateKey) -> PublicKey:
    """Return the public half of a private key."""
    return private_key.public_key()


def generate_private_key(alg: str, *, rsa_bits: int = 3072) -> PrivateKey:
    """Generate a fresh signing key for ``alg``. Intended for development and tests."""
    if alg in _RSA_ALGORITHMS:
        return rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)
    curves = {"ES256": ec.SECP256R1(), "ES384": ec.SECP384R1(), "ES512": ec.SECP521R1()}
    if alg in curves:
        return ec.generate_private_key(curves[alg])
    if alg == "EdDSA":
        return ed25519.Ed25519PrivateKey.generate()
    raise ConfigurationError(f"cannot generate a key for algorithm {alg!r}")


def load_private_key_pem(data: bytes) -> PrivateKey:
    """Load an unencrypted PEM private key.

    Raises:
        ConfigurationError: If the PEM is not a supported private signing key.
    """
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError):
        raise ConfigurationError("private key PEM could not be loaded") from None
    if not isinstance(
        key,
        rsa.RSAPrivateKey
        | ec.EllipticCurvePrivateKey
        | ed25519.Ed25519PrivateKey
        | ed448.Ed448PrivateKey,
    ):
        raise ConfigurationError("unsupported private key type")
    return key


def private_key_to_pem(private_key: PrivateKey) -> bytes:
    """Serialise a private key as unencrypted PKCS#8 PEM (development only)."""
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def sign_raw(signing_input: bytes, private_key: PrivateKey, alg: str) -> bytes:
    """Sign arbitrary JWS signing input. Test helpers use this to build malformed tokens."""
    if alg in FORBIDDEN_ALGORITHMS:
        raise ConfigurationError(f"algorithm {alg!r} is not permitted for signing")
    algorithm = _JWS.get_algorithm_by_name(alg)
    return algorithm.sign(signing_input, algorithm.prepare_key(private_key))


def public_key_pem(public_key: PublicKey) -> bytes:
    """Serialise a public key as SubjectPublicKeyInfo PEM."""
    return public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def sign_compact(
    payload: Mapping[str, object],
    private_key: PrivateKey,
    *,
    alg: str,
    kid: str | None,
    typ: str = TXN_TOKEN_TYP,
    extra_headers: Mapping[str, object] | None = None,
) -> str:
    """Produce a compact JWS over a JSON payload.

    This is a primitive. Only the Transaction Token Service and test helpers hold private keys and
    call it; resource services never do (CLAUDE.md invariant 6).
    """
    if alg in FORBIDDEN_ALGORITHMS:
        raise ConfigurationError(f"algorithm {alg!r} is not permitted for signing")
    if alg not in algorithms_for_key(private_key.public_key()):
        raise ConfigurationError("algorithm is incompatible with the signing key")
    headers: dict[str, object] = {**(extra_headers or {}), "typ": typ, "alg": alg}
    if kid is not None:
        headers["kid"] = kid
    return _JWS.encode(compact_dumps(payload), private_key, algorithm=alg, headers=headers)
