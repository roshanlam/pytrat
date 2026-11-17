"""Trusted verification keys.

Keys always come from trusted configuration and are selected by ``kid``. A token can never supply
or point to its own key (CLAUDE.md invariant 3). Key sets are immutable; refreshing a remote JWKS
produces a new set that is swapped in atomically (see ``pytrat.client.jwks``).
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Self

from pytrat.core._json import strict_loads
from pytrat.core.crypto import PublicKey, algorithms_for_key, load_public_jwk, public_jwk
from pytrat.core.errors import ConfigurationError, ReasonCode

_MAX_JWKS_BYTES = 256 * 1024


@dataclass(frozen=True, slots=True)
class VerificationKey:
    """A trusted public key and the algorithms it may verify."""

    kid: str
    public_key: PublicKey
    algorithms: frozenset[str]

    def __repr__(self) -> str:
        return f"VerificationKey(kid={self.kid!r}, algorithms={sorted(self.algorithms)})"

    @classmethod
    def from_public_key(cls, kid: str, public_key: PublicKey, alg: str | None = None) -> Self:
        """Wrap a key object, optionally restricting it to a single algorithm."""
        algorithms = algorithms_for_key(public_key)
        if alg is not None:
            if alg not in algorithms:
                raise ConfigurationError(
                    "algorithm is incompatible with the key", ReasonCode.KEY_UNKNOWN
                )
            algorithms = frozenset({alg})
        return cls(kid=kid, public_key=public_key, algorithms=algorithms)

    def to_jwk(self) -> dict[str, object]:
        """Export as a public JWK (uses the first algorithm alphabetically if several apply)."""
        return public_jwk(self.public_key, kid=self.kid, alg=min(self.algorithms))


class KeyProvider(Protocol):
    """Lookup of trusted verification keys. Implementations must not perform I/O."""

    def get(self, kid: str | None) -> VerificationKey | None:
        """Return the trusted key for ``kid``, or None if there is none."""
        ...


class StaticKeySet:
    """An immutable set of trusted verification keys indexed by ``kid``."""

    __slots__ = ("_keys",)

    def __init__(self, keys: Iterable[VerificationKey]) -> None:
        indexed: dict[str, VerificationKey] = {}
        for key in keys:
            if key.kid in indexed:
                raise ConfigurationError(f"duplicate kid {key.kid!r}", ReasonCode.KEY_UNKNOWN)
            indexed[key.kid] = key
        self._keys: Mapping[str, VerificationKey] = indexed

    @classmethod
    def from_jwks(cls, jwks: Mapping[str, object]) -> Self:
        """Build from a parsed JWKS document (RFC 7517 §5).

        Raises:
            ConfigurationError: If the document or any key is invalid. One bad key rejects the set.
        """
        raw_keys = jwks.get("keys")
        if not isinstance(raw_keys, list):
            raise ConfigurationError("JWKS must contain a 'keys' array", ReasonCode.KEY_UNKNOWN)
        keys: list[VerificationKey] = []
        for raw in raw_keys:
            if not isinstance(raw, Mapping):
                raise ConfigurationError("JWKS entries must be objects", ReasonCode.KEY_UNKNOWN)
            kid = raw.get("kid")
            if not isinstance(kid, str) or not kid:
                raise ConfigurationError(
                    "every trusted JWK must have a 'kid'", ReasonCode.KEY_UNKNOWN
                )
            public_key, algorithms = load_public_jwk(raw)
            keys.append(VerificationKey(kid=kid, public_key=public_key, algorithms=algorithms))
        return cls(keys)

    @classmethod
    def from_jwks_bytes(cls, data: bytes) -> Self:
        """Parse a serialized JWKS document."""
        if len(data) > _MAX_JWKS_BYTES:
            raise ConfigurationError("JWKS document is too large", ReasonCode.KEY_UNKNOWN)
        try:
            document = strict_loads(data)
        except (ValueError, UnicodeDecodeError):
            raise ConfigurationError("JWKS is not valid JSON", ReasonCode.KEY_UNKNOWN) from None
        if not isinstance(document, Mapping):
            raise ConfigurationError("JWKS must be a JSON object", ReasonCode.KEY_UNKNOWN)
        return cls.from_jwks(document)

    @classmethod
    def from_jwks_file(cls, path: str | Path) -> Self:
        """Load a JWKS document from a local file."""
        return cls.from_jwks_bytes(Path(path).read_bytes())

    def get(self, kid: str | None) -> VerificationKey | None:
        """Return the key for ``kid``.

        A token without ``kid`` resolves only when the set holds exactly one key; the verifier
        rejects missing ``kid`` before this unless ``require_kid=False``.
        """
        if kid is None:
            return next(iter(self._keys.values())) if len(self._keys) == 1 else None
        return self._keys.get(kid)

    @property
    def kids(self) -> frozenset[str]:
        """Identifiers of the keys in this set."""
        return frozenset(self._keys)

    def to_jwks(self) -> dict[str, object]:
        """Export the set as a public JWKS document."""
        return {"keys": [key.to_jwk() for key in self._keys.values()]}

    def to_json(self) -> str:
        """Export the set as a JSON string."""
        return json.dumps(self.to_jwks(), indent=2)

    def __len__(self) -> int:
        return len(self._keys)

    def __repr__(self) -> str:
        return f"StaticKeySet(kids={sorted(self._keys)})"
