"""Transaction identifiers.

txn-tokens-11 §9.2 and §13.2: ``txn`` is a unique transaction identifier and SHOULD be unique within
the Trust Domain. PyTraT uses UUIDv7 (RFC 9562 §5.7): 74 random bits make collisions negligible and
the time-ordered prefix gives good index locality in the issuance log.
"""

from __future__ import annotations

import secrets
import uuid
from collections.abc import Callable
from typing import Final

from pytrat.core.clock import Clock, SystemClock

__all__ = ["new_txn_id", "uuid7_from"]

_MAX_UNIX_MS: Final = (1 << 48) - 1
_RANDOM_BYTES: Final = 10


def uuid7_from(unix_ms: int, random_bytes: bytes) -> uuid.UUID:
    """Build a UUIDv7 from a millisecond timestamp and 10 random bytes (RFC 9562 §5.7).

    Layout: 48-bit ``unix_ts_ms`` | 4-bit version (7) | 12-bit ``rand_a`` | 2-bit variant (10) |
    62-bit ``rand_b``.

    Raises:
        ValueError: If the timestamp does not fit in 48 bits or ``random_bytes`` is not 10 bytes.
    """
    if not 0 <= unix_ms <= _MAX_UNIX_MS:
        raise ValueError("unix_ms must fit in 48 bits")
    if len(random_bytes) != _RANDOM_BYTES:
        raise ValueError("random_bytes must be exactly 10 bytes")
    rand = int.from_bytes(random_bytes, "big")
    rand_a = (rand >> 68) & 0xFFF
    rand_b = rand & ((1 << 62) - 1)
    value = (unix_ms << 80) | (0x7 << 76) | (rand_a << 64) | (0b10 << 62) | rand_b
    return uuid.UUID(int=value)


def _local_uuid7(clock: Clock) -> uuid.UUID:
    return uuid7_from(int(clock.now() * 1000), secrets.token_bytes(_RANDOM_BYTES))


def _stdlib_uuid7() -> Callable[[], uuid.UUID] | None:
    factory: object = getattr(uuid, "uuid7", None)  # Python 3.14+
    return factory if callable(factory) else None


def new_txn_id(clock: Clock | None = None) -> str:
    """Return a new UUIDv7 transaction identifier as a string.

    Uses :func:`uuid.uuid7` when the standard library provides it (Python 3.14+) and no clock is
    injected; otherwise a local RFC 9562 implementation using ``clock`` (system clock by default).
    """
    stdlib = _stdlib_uuid7()
    if stdlib is not None and clock is None:
        return str(stdlib())
    return str(_local_uuid7(clock or SystemClock()))
