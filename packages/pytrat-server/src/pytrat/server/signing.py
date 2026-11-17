"""Txn-Token signing: the only place in PyTraT that holds signing keys.

:class:`Signer` is the port; :class:`KeyRingSigner` is the in-process implementation and
:class:`FileKeySigner` loads it from PEM files. A KMS or HSM adapter implements :class:`Signer`
without exposing key material.

Rotation (txn-tokens-11 §13.11): exactly one key is ``active`` and signs; ``retiring`` keys are
still published in the JWKS so tokens they signed keep verifying until they expire. Operators
remove a retiring key only after ``max_lifetime + leeway`` has passed since it stopped signing.
"""

from __future__ import annotations

import stat
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, Self

from pytrat.core.constants import TXN_TOKEN_TYP
from pytrat.core.crypto import PrivateKey, load_private_key_pem, public_jwk, sign_compact
from pytrat.core.errors import ConfigurationError
from pytrat.server.settings import KeyState, TtsSettings

__all__ = ["FileKeySigner", "KeyRingSigner", "Signer", "SigningKey"]

_GROUP_OR_OTHER = stat.S_IRWXG | stat.S_IRWXO


class Signer(Protocol):
    """Signs Txn-Token payloads and publishes the matching public keys."""

    def sign(self, payload: Mapping[str, object]) -> str:
        """Return a compact JWS with ``typ: txntoken+jwt`` and a ``kid`` (txn-tokens-11 §9.1)."""
        ...

    def jwks(self) -> dict[str, object]:
        """Return the public JWKS: every key whose tokens may still be in circulation."""
        ...


@dataclass(frozen=True, slots=True)
class SigningKey:
    """A private signing key and its lifecycle state."""

    kid: str
    alg: str
    private_key: PrivateKey = field(repr=False)
    state: KeyState = KeyState.ACTIVE


class KeyRingSigner:
    """Signs with the single active key; publishes active and retiring keys."""

    __slots__ = ("_active", "_jwks")

    def __init__(self, keys: Iterable[SigningKey]) -> None:
        """Validate the ring.

        Raises:
            ConfigurationError: Unless exactly one key is active and kids are unique, or if a key
                does not match its algorithm.
        """
        ring = tuple(keys)
        kids = [key.kid for key in ring]
        if len(set(kids)) != len(kids):
            raise ConfigurationError("signing key kids must be unique")
        active = [key for key in ring if key.state is KeyState.ACTIVE]
        if len(active) != 1:
            raise ConfigurationError("exactly one signing key must be active")
        self._active = active[0]
        # Built once at startup: public_jwk also checks each key matches its algorithm.
        self._jwks: tuple[dict[str, object], ...] = tuple(
            public_jwk(key.private_key.public_key(), kid=key.kid, alg=key.alg) for key in ring
        )

    @property
    def active_kid(self) -> str:
        """``kid`` of the key that signs new tokens."""
        return self._active.kid

    def sign(self, payload: Mapping[str, object]) -> str:
        """Sign ``payload`` with the active key; see :class:`Signer`."""
        active = self._active
        return sign_compact(
            payload, active.private_key, alg=active.alg, kid=active.kid, typ=TXN_TOKEN_TYP
        )

    def jwks(self) -> dict[str, object]:
        """Return the public JWKS; see :class:`Signer`."""
        return {"keys": [dict(jwk) for jwk in self._jwks]}

    def __repr__(self) -> str:
        return f"{type(self).__name__}(active_kid={self._active.kid!r}, keys={len(self._jwks)})"


class FileKeySigner(KeyRingSigner):
    """A :class:`KeyRingSigner` whose keys are unencrypted PEM files (development and tests)."""

    __slots__ = ()

    @staticmethod
    def load_key_file(path: Path, *, allow_insecure_permissions: bool = False) -> PrivateKey:
        """Load a PEM private key, refusing files readable or writable by group or others.

        Raises:
            ConfigurationError: If the file is missing, too permissive or not a private key.
        """
        try:
            mode = path.stat().st_mode
            if mode & _GROUP_OR_OTHER and not allow_insecure_permissions:
                raise ConfigurationError(
                    "signing key file is accessible by group or others (chmod 600 it)"
                )
            data = path.read_bytes()
        except OSError:
            raise ConfigurationError("signing key file could not be read") from None
        return load_private_key_pem(data)

    @classmethod
    def from_settings(
        cls, settings: TtsSettings, *, allow_insecure_permissions: bool = False
    ) -> Self:
        """Load every configured signing key.

        Args:
            settings: TTS settings.
            allow_insecure_permissions: Skip the file-mode check. For tests only.

        Raises:
            ConfigurationError: If any key cannot be loaded or the ring is invalid.
        """
        return cls(
            SigningKey(
                kid=key.kid,
                alg=key.alg,
                private_key=cls.load_key_file(
                    key.private_key_path, allow_insecure_permissions=allow_insecure_permissions
                ),
                state=key.state,
            )
            for key in settings.signing_keys
        )
