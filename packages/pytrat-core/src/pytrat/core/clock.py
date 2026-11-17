"""Injectable time source.

Security decisions depend on the current time, so time is always injected rather than read inline.
"""

from __future__ import annotations

import time
from typing import Protocol


class Clock(Protocol):
    """Source of the current time as POSIX seconds."""

    def now(self) -> float:
        """Return the current time in seconds since the epoch."""
        ...


class SystemClock:
    """Wall-clock time from the operating system."""

    __slots__ = ()

    def now(self) -> float:
        """Return :func:`time.time`."""
        return time.time()


class FrozenClock:
    """A clock that only moves when told to. Intended for tests and simulations."""

    __slots__ = ("_now",)

    def __init__(self, now: float = 1_795_000_000.0) -> None:
        self._now = now

    def now(self) -> float:
        """Return the frozen time."""
        return self._now

    def advance(self, seconds: float) -> None:
        """Move the clock forward by ``seconds``."""
        self._now += seconds

    def set(self, now: float) -> None:
        """Set the clock to an absolute time."""
        self._now = now
