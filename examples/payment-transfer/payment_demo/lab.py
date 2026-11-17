"""Development key material and configuration for the demo.

Everything is generated fresh into a working directory: no key material is committed. Private
keys are written with mode 0600, exactly as the reference TTS requires.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from pytrat.core import SecretToken, StaticKeySet, VerificationKey, WorkloadKeys
from pytrat.core.crypto import PrivateKey, generate_private_key, private_key_to_pem, sign_compact

TRUST_DOMAIN = "payments.internal"
TTS_ISSUER = "https://tts.payments.internal"
IDP_ISSUER = "https://idp.example"
API_AUDIENCE = "https://api.payments.example"
SCOPE = "payments.transfer"
TRANSFER_FIELDS = ("source_account", "destination_account", "amount_minor", "currency")
ALG = "ES256"


@dataclass(frozen=True, slots=True)
class Urls:
    """Where each service is reachable."""

    tts: str = "https://tts.payments.internal"
    gateway: str = "https://gateway.payments.internal"
    payment: str = "https://payment.payments.internal"
    ledger: str = "https://ledger.payments.internal"

    @property
    def token_endpoint(self) -> str:
        """The TTS token endpoint."""
        return f"{self.tts}/token"

    @property
    def insecure_localhost(self) -> bool:
        """True when running the services over plain HTTP on loopback (local multi-process mode)."""
        return self.tts.startswith("http://127.0.0.1")


@dataclass(frozen=True, slots=True)
class Lab:
    """Generated keys and configuration shared by the four services."""

    directory: Path
    urls: Urls
    keys: Mapping[str, PrivateKey] = field(repr=False)

    @classmethod
    def create(cls, directory: Path, urls: Urls | None = None) -> Lab:
        """Generate keys (TTS, identity provider, gateway, payment service) into ``directory``."""
        directory.mkdir(parents=True, exist_ok=True)
        names = ("tts", "idp", "api-gateway", "payment-service")
        keys = {name: generate_private_key(ALG) for name in names}
        for name, key in keys.items():
            _write_private(directory / f"{name}.pem", private_key_to_pem(key))
        return cls(directory=directory, urls=urls or Urls(), keys=keys)

    def pem(self, name: str) -> Path:
        """Path of a generated private key."""
        return self.directory / f"{name}.pem"

    def public_jwks(self, *names: str) -> dict[str, object]:
        """Public JWKS for the named keys; the kid is the key's name."""
        return StaticKeySet(
            VerificationKey.from_public_key(name, self.keys[name].public_key(), ALG)
            for name in names
        ).to_jwks()

    def tts_keys(self) -> StaticKeySet:
        """The TTS verification keys every resource service trusts."""
        return StaticKeySet.from_jwks(self.public_jwks("tts"))

    def workload_keys(self) -> WorkloadKeys:
        """Keys resource services trust for workload authentication, by owning workload.

        A workload JWT authenticates only the workload that owns the verifying key.
        """
        return WorkloadKeys(
            {
                name: StaticKeySet.from_jwks(self.public_jwks(name))
                for name in ("api-gateway", "payment-service")
            }
        )

    def user_access_token(self, subject: str = "user:123") -> SecretToken:
        """An access token the identity provider issued after the user logged in."""
        now = int(time.time())
        claims = {
            "iss": IDP_ISSUER,
            "aud": API_AUDIENCE,
            "sub": subject,
            "scope": SCOPE,
            "iat": now,
            "exp": now + 600,
            "client_id": "web-app",
            "jti": uuid.uuid4().hex,
        }
        raw = sign_compact(claims, self.keys["idp"], alg=ALG, kid="idp", typ="at+jwt")
        return SecretToken(raw)

    def tts_settings(self) -> dict[str, object]:
        """Configuration document for the reference TTS (see packages/pytrat-server/examples)."""
        (self.directory / "idp.jwks.json").write_text(json.dumps(self.public_jwks("idp")))
        return {
            "trust_domain": TRUST_DOMAIN,
            "issuer": TTS_ISSUER,
            "token_endpoint": self.urls.token_endpoint,
            "token_lifetime_seconds": 60,
            "algorithms": [ALG],
            "audit_db_path": "tts-audit.sqlite3",
            "signing_keys": [
                {"kid": "tts", "alg": ALG, "private_key_path": "tts.pem", "state": "active"}
            ],
            "workloads": [
                {"id": "api-gateway", "jwks": self.public_jwks("api-gateway")},
                {"id": "payment-service", "jwks": self.public_jwks("payment-service")},
            ],
            "subject_tokens": {
                "jwt_access_token": [
                    {"issuer": IDP_ISSUER, "jwks_path": "idp.jwks.json", "audience": API_AUDIENCE}
                ]
            },
            "issuance_policy": {
                "workloads": {
                    "api-gateway": {
                        "scopes": [SCOPE],
                        "tctx": {
                            "source_account": "string",
                            "destination_account": "string",
                            "amount_minor": "integer",
                            "currency": "string",
                        },
                        "rctx": {"channel": "string"},
                    }
                }
            },
        }


def _write_private(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
