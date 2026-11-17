"""Per-workload rate limiting at the token endpoint.

:class:`RateLimiter` is the port (a Redis implementation can follow for multi-instance
deployments); :class:`TokenBucketRateLimiter` is an in-memory, per-process token bucket.
"""

from __future__ import annotations

import threading
from typing import Protocol

from pytrat.core.clock import Clock
from pytrat.core.errors import ReasonCode
from pytrat.server.errors import OAuthError, OAuthErrorCode

__all__ = ["RateLimiter", "TokenBucketRateLimiter"]


class RateLimiter(Protocol):
    """Admits or refuses one request for a key."""

    def acquire(self, key: str) -> None:
        """Consume one unit for ``key``.

        Raises:
            OAuthError: ``slow_down`` (HTTP 429) / ``RATE_LIMITED`` when over the limit.
        """
        ...


class TokenBucketRateLimiter:
    """A token bucket per key: ``burst`` capacity, refilled at ``rate`` per second.

    Keys are authenticated workload ids, so the number of buckets is bounded by the registry;
    ``max_keys`` is a further guard that refuses (fails closed) rather than evicting.
    """

    __slots__ = ("_buckets", "_burst", "_clock", "_lock", "_max_keys", "_rate")

    def __init__(self, rate: float, burst: int, clock: Clock, *, max_keys: int = 10_000) -> None:
        if rate <= 0 or burst < 1:
            raise ValueError("rate must be positive and burst at least 1")
        self._rate = rate
        self._burst = float(burst)
        self._clock = clock
        self._max_keys = max_keys
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def acquire(self, key: str) -> None:
        """Consume one unit for ``key``; see :class:`RateLimiter`."""
        now = self._clock.now()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                if len(self._buckets) >= self._max_keys:
                    raise _limited()
                tokens = self._burst
            else:
                tokens, updated = bucket
                tokens = min(self._burst, tokens + max(0.0, now - updated) * self._rate)
            if tokens < 1.0:
                self._buckets[key] = (tokens, now)
                raise _limited()
            self._buckets[key] = (tokens - 1.0, now)


def _limited() -> OAuthError:
    return OAuthError(OAuthErrorCode.SLOW_DOWN, "too many requests", ReasonCode.RATE_LIMITED)
