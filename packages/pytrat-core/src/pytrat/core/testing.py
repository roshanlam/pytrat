"""Test helpers: generated keys and a token factory, including deliberately malformed tokens.

Never import this module from production code; an import-linter contract enforces that.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Self

from pytrat.core.clock import FrozenClock
from pytrat.core.constants import TXN_TOKEN_TYP
from pytrat.core.crypto import (
    PrivateKey,
    PublicKey,
    generate_private_key,
    public_jwk,
    public_key_pem,
    sign_compact,
    sign_raw,
)
from pytrat.core.keys import StaticKeySet, VerificationKey
from pytrat.core.validation import TokenVerifier, VerifierSettings

__all__ = ["FrozenClock", "TestKey", "TokenFactory", "b64url", "generate_test_key"]


def b64url(data: bytes) -> str:
    """Unpadded base64url encoding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@dataclass(frozen=True, slots=True)
class TestKey:
    """A generated signing key pair."""

    __test__ = False  # not a pytest test class

    kid: str
    alg: str
    private_key: PrivateKey = field(repr=False)

    @property
    def public_key(self) -> PublicKey:
        """The public half."""
        return self.private_key.public_key()

    @property
    def verification_key(self) -> VerificationKey:
        """The public half as a trusted verification key restricted to :attr:`alg`."""
        return VerificationKey.from_public_key(self.kid, self.public_key, self.alg)

    def jwk(self) -> dict[str, object]:
        """The public JWK."""
        return public_jwk(self.public_key, kid=self.kid, alg=self.alg)

    def key_set(self, *others: TestKey) -> StaticKeySet:
        """A trusted key set containing this key and ``others``."""
        return StaticKeySet([self.verification_key, *(o.verification_key for o in others)])


def generate_test_key(alg: str = "ES256", kid: str | None = None) -> TestKey:
    """Generate a fresh key pair. RSA keys are 2048-bit to keep tests fast."""
    private_key = generate_private_key(alg, rsa_bits=2048)
    return TestKey(
        kid=kid or f"test-{alg.lower()}-{uuid.uuid4().hex[:8]}", alg=alg, private_key=private_key
    )


@dataclass(slots=True)
class TokenFactory:
    """Mints Transaction Tokens for tests.

    Defaults produce a valid token for ``trust_domain`` at the clock's current time.
    """

    __test__ = False

    key: TestKey
    trust_domain: str = "payments.internal"
    clock: FrozenClock = field(default_factory=FrozenClock)
    lifetime: int = 60
    defaults: Mapping[str, object] = field(default_factory=dict)

    @classmethod
    def create(cls, alg: str = "ES256", **kwargs: object) -> Self:
        """Build a factory with a freshly generated key."""
        return cls(key=generate_test_key(alg), **kwargs)  # type: ignore[arg-type]

    def claims(self, **overrides: object) -> dict[str, object]:
        """A valid claim set with ``overrides`` applied; an override of ``None`` drops it."""
        now = int(self.clock.now())
        claims: dict[str, object] = {
            "iss": "https://tts.test",
            "aud": self.trust_domain,
            "iat": now,
            "exp": now + self.lifetime,
            "txn": f"txn-{uuid.uuid4().hex[:12]}",
            "sub": "user:123",
            "scope": "payments.transfer",
            "req_wl": "api-gateway",
            "tctx": {
                "source_account": "account-A",
                "destination_account": "account-B",
                "amount_minor": 10000,
                "currency": "USD",
            },
            "rctx": {"authentication_method": "oauth2"},
            **self.defaults,
        }
        for name, value in overrides.items():
            if value is None:
                claims.pop(name, None)
            else:
                claims[name] = value
        return claims

    def mint(
        self,
        *,
        headers: Mapping[str, object] | None = None,
        key: TestKey | None = None,
        **claim_overrides: object,
    ) -> str:
        """Sign a token. ``headers`` are added to (or override) the JOSE header."""
        signer = key or self.key
        header_overrides = dict(headers or {})
        typ = header_overrides.pop("typ", TXN_TOKEN_TYP)
        kid = header_overrides.pop("kid", signer.kid)
        return sign_compact(
            self.claims(**claim_overrides),
            signer.private_key,
            alg=signer.alg,
            kid=kid,  # type: ignore[arg-type]
            typ=typ,  # type: ignore[arg-type]
            extra_headers=header_overrides,
        )

    def mint_payload(self, payload: Mapping[str, object] | bytes, **headers: object) -> str:
        """Sign an arbitrary payload. Raw bytes allow duplicate keys and other malformed JSON."""
        header = {"typ": TXN_TOKEN_TYP, "alg": self.key.alg, "kid": self.key.kid, **headers}
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        signing_input = f"{b64url(json.dumps(header).encode())}.{b64url(body)}"
        signature = sign_raw(signing_input.encode(), self.key.private_key, self.key.alg)
        return f"{signing_input}.{b64url(signature)}"

    def unsigned(self, **claim_overrides: object) -> str:
        """A token with ``alg: none`` and an empty signature."""
        header = {"typ": TXN_TOKEN_TYP, "alg": "none", "kid": self.key.kid}
        payload = self.claims(**claim_overrides)
        return f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(payload).encode())}."

    def hmac_with_public_key(self, **claim_overrides: object) -> str:
        """The classic key-confusion attack: HS256 keyed with the verifier's public key."""
        header = {"typ": TXN_TOKEN_TYP, "alg": "HS256", "kid": self.key.kid}
        payload = self.claims(**claim_overrides)
        signing_input = (
            f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(payload).encode())}"
        )
        secret = public_key_pem(self.key.public_key)
        signature = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
        return f"{signing_input}.{b64url(signature)}"

    def verifier(self, settings: VerifierSettings | None = None) -> TokenVerifier:
        """A verifier trusting this factory's key and sharing its clock."""
        return TokenVerifier(
            settings
            or VerifierSettings(
                trust_domain=self.trust_domain, algorithms=frozenset({self.key.alg})
            ),
            self.key.key_set(),
            clock=self.clock,
        )
