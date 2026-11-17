"""Wrapper that keeps credentials out of logs, exceptions and ``repr``."""

from __future__ import annotations

import hashlib
import hmac
from typing import final


def token_digest(raw_token: str) -> str:
    """Return the SHA-256 hex digest of a token, the only form of a token that may be logged.

    txn-tokens-11 §15.2: complete tokens MUST NOT be logged; a hash MAY be.
    """
    return hashlib.sha256(raw_token.encode("ascii", errors="replace")).hexdigest()


@final
class SecretToken:
    """An opaque credential whose value is only reachable through :meth:`reveal`.

    ``str``, ``repr`` and formatting show a short digest instead of the value, so accidentally
    logging or raising one never discloses it. Equality is constant-time.
    """

    __slots__ = ("_digest", "_value")

    def __init__(self, value: str) -> None:
        if not value:
            raise ValueError("SecretToken value must be non-empty")
        self._value = value
        self._digest = token_digest(value)

    def reveal(self) -> str:
        """Return the raw credential. Call only at the point of transmission."""
        return self._value

    @property
    def digest(self) -> str:
        """SHA-256 hex digest of the credential; safe to log."""
        return self._digest

    def __repr__(self) -> str:
        return f"SecretToken(sha256={self._digest[:12]}…)"

    __str__ = __repr__

    def __format__(self, format_spec: str) -> str:
        return repr(self)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SecretToken):
            return NotImplemented
        return hmac.compare_digest(self._value, other._value)

    def __hash__(self) -> int:
        return hash(self._digest)

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("SecretToken cannot be pickled")
