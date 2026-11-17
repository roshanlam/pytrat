"""Optional replay protection.

txn-tokens-11 §13.1: Txn-Tokens are not resistant to replay, and §13.2 notes strict single-use
checks may not be feasible because a token is legitimately reused within one transaction.

PyTraT profile P8: replay protection is opt-in per operation. A route marked single-use records
``(txn, operation)`` and rejects a second use until the token expires.
"""

from __future__ import annotations

import heapq
import threading
from typing import Protocol

from pytrat.core.clock import Clock, SystemClock
from pytrat.core.errors import AuthorizationError, DependencyError, ReasonCode


def replay_key(txn: str, operation: str) -> str:
    """Build the store key for one use of a transaction on one operation."""
    return f"{len(txn)}:{txn}|{operation}"


class ReplayStore(Protocol):
    """Records first uses. Multi-instance deployments need a shared, consistent implementation."""

    def record_once(self, key: str, expires_at: float) -> None:
        """Record ``key`` until ``expires_at``.

        Raises:
            AuthorizationError: ``REPLAY_DETECTED`` if ``key`` is already recorded.
            DependencyError: If the store cannot record (the caller must deny).
        """
        ...


class InMemoryReplayStore:
    """A bounded, per-process replay store.

    Only correct for a single process. When full of unexpired entries it refuses new ones
    (fail closed) rather than evicting live entries, which would re-enable replay.
    """

    __slots__ = ("_clock", "_entries", "_expiry", "_lock", "_max_entries")

    def __init__(self, max_entries: int = 100_000, clock: Clock | None = None) -> None:
        self._max_entries = max_entries
        self._clock: Clock = clock or SystemClock()
        self._entries: dict[str, float] = {}
        self._expiry: list[tuple[float, str]] = []
        self._lock = threading.Lock()

    def record_once(self, key: str, expires_at: float) -> None:
        """Record ``key``; see :meth:`ReplayStore.record_once`."""
        now = self._clock.now()
        with self._lock:
            self._purge(now)
            existing = self._entries.get(key)
            if existing is not None and existing > now:
                raise AuthorizationError(ReasonCode.REPLAY_DETECTED, "operation already performed")
            if len(self._entries) >= self._max_entries:
                raise DependencyError("replay store is full")
            self._entries[key] = expires_at
            heapq.heappush(self._expiry, (expires_at, key))

    def __len__(self) -> int:
        return len(self._entries)

    def _purge(self, now: float) -> None:
        while self._expiry and self._expiry[0][0] <= now:
            expires_at, key = heapq.heappop(self._expiry)
            if self._entries.get(key) == expires_at:
                del self._entries[key]
