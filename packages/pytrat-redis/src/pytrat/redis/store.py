"""A :class:`~pytrat.core.replay.ReplayStore` shared by every instance through Redis.

txn-tokens-11 §13.1: Txn-Tokens are not resistant to replay. PyTraT profile P8 makes single-use
opt-in per operation; :class:`~pytrat.core.replay.InMemoryReplayStore` enforces it only within one
process. This store enforces it across every process that shares one Redis.

Each first use is a single atomic ``SET key 1 NX PX <ttl>``: Redis either creates the key (first
use) or leaves it untouched (replay). There is no read-then-write window in which two instances
can both observe "unused".
"""

from __future__ import annotations

import hashlib
import logging
import math
from datetime import timedelta
from typing import Final, Protocol, Self

import redis
from redis.backoff import NoBackoff
from redis.exceptions import RedisError
from redis.retry import Retry

from pytrat.core.clock import Clock, SystemClock
from pytrat.core.errors import (
    AuthorizationError,
    ConfigurationError,
    DependencyError,
    ReasonCode,
)

__all__ = ["DEFAULT_PREFIX", "RedisClient", "RedisReplayStore"]

_logger = logging.getLogger(__name__)

DEFAULT_PREFIX: Final = "pytrat:replay:"
_MARKER: Final = "1"
_DEFAULT_RETENTION_MARGIN: Final = timedelta(seconds=60)
_MAX_RETENTION_MARGIN: Final = timedelta(hours=1)
_DEFAULT_MAX_TTL: Final = timedelta(hours=1)
_DEFAULT_SOCKET_TIMEOUT: Final = 0.5


class RedisClient(Protocol):
    """The one Redis command this store needs. ``redis.Redis`` satisfies it.

    Must be a synchronous client: an asyncio client returns an awaitable, which the store treats
    as an unexpected reply and denies.
    """

    def set(self, name: str, value: str, *, nx: bool, px: int) -> object:
        """``SET name value NX PX px``; ``True`` if set, ``None`` if the key already existed."""
        ...


class RedisReplayStore:
    """Records first uses in Redis so every instance sharing it rejects a replay.

    Guarantees:

    * Atomic: one ``SET NX PX`` per call, so N concurrent callers on one key get exactly one
      success and N-1 ``REPLAY_DETECTED``, whichever instances they run on.
    * Fail closed: any Redis error, timeout or unexpected reply raises :class:`DependencyError`.
    * Keys are ``prefix + sha256(key)``; raw ``txn`` values never reach Redis, and neither keys
      nor connection URLs are logged.
    * A record is kept until ``expires_at + retention_margin`` measured from the injected clock,
      so it outlives the verifier's ``exp`` leeway and does not depend on Redis's own clock.

    The store is synchronous. The FastAPI integration calls it on the event loop, so the client
    must have short socket timeouts; :meth:`from_url` configures them.

    Args:
        client: A synchronous Redis client (``redis.Redis``), already configured.
        prefix: Namespace for keys, so several services or environments can share one Redis.
        clock: Time source used to turn ``expires_at`` into a relative TTL.
        retention_margin: Extra time a record is kept past ``expires_at``. Must cover the
            verifier's ``leeway`` plus clock skew between instances. At most one hour.
        max_ttl: Largest accepted ``expires_at - now``. Longer requests are refused (deny), not
            truncated, because truncating would re-open replay before the token expires.

    Raises:
        ConfigurationError: If ``prefix``, ``retention_margin`` or ``max_ttl`` is invalid.
    """

    __slots__ = ("_client", "_clock", "_margin_seconds", "_max_ttl_seconds", "_prefix")

    def __init__(
        self,
        client: RedisClient,
        *,
        prefix: str = DEFAULT_PREFIX,
        clock: Clock | None = None,
        retention_margin: timedelta = _DEFAULT_RETENTION_MARGIN,
        max_ttl: timedelta = _DEFAULT_MAX_TTL,
    ) -> None:
        if not prefix or not prefix.isprintable() or " " in prefix:
            raise ConfigurationError("replay key prefix must be non-empty printable text")
        if not timedelta(0) <= retention_margin <= _MAX_RETENTION_MARGIN:
            raise ConfigurationError("retention_margin must be between 0 and 1 hour")
        if max_ttl <= timedelta(0):
            raise ConfigurationError("max_ttl must be positive")
        self._client = client
        self._prefix = prefix
        self._clock: Clock = clock or SystemClock()
        self._margin_seconds = retention_margin.total_seconds()
        self._max_ttl_seconds = max_ttl.total_seconds()

    @classmethod
    def from_url(
        cls,
        url: str,
        *,
        prefix: str = DEFAULT_PREFIX,
        clock: Clock | None = None,
        retention_margin: timedelta = _DEFAULT_RETENTION_MARGIN,
        max_ttl: timedelta = _DEFAULT_MAX_TTL,
        socket_timeout: float = _DEFAULT_SOCKET_TIMEOUT,
    ) -> Self:
        """Build a store with a new client for ``url`` (``redis://``, ``rediss://``, ``unix://``).

        The client uses ``socket_timeout`` for both connect and command timeouts and performs no
        retries: a retried ``SET NX`` whose first attempt landed would report a false replay, and
        retries multiply the time the event loop can be blocked. No connection is made here.

        Raises:
            ConfigurationError: If the URL or any option is invalid. The message never contains
                the URL, which may carry a password.
        """
        if not (math.isfinite(socket_timeout) and socket_timeout > 0):
            raise ConfigurationError("socket_timeout must be a positive number of seconds")
        try:
            client = redis.Redis.from_url(
                url,
                socket_timeout=socket_timeout,
                socket_connect_timeout=socket_timeout,
                retry=Retry(NoBackoff(), 0),
            )
        except (ValueError, TypeError):
            raise ConfigurationError("invalid Redis URL") from None
        return cls(
            client, prefix=prefix, clock=clock, retention_margin=retention_margin, max_ttl=max_ttl
        )

    def record_once(self, key: str, expires_at: float) -> None:
        """Record ``key`` until ``expires_at`` (plus the retention margin).

        Raises:
            AuthorizationError: ``REPLAY_DETECTED`` if ``key`` is already recorded.
            DependencyError: If the expiry is not finite, already past (including the margin) or
                beyond ``max_ttl``, or if Redis fails, times out or replies unexpectedly. The
                caller must deny.
        """
        ttl_ms = self._ttl_ms(expires_at)
        try:
            reply = self._client.set(self._redis_key(key), _MARKER, nx=True, px=ttl_ms)
        except (RedisError, OSError) as exc:
            # The exception text can name hosts; only its type is logged.
            _logger.warning("replay store unavailable (%s)", type(exc).__name__)
            raise DependencyError("replay store is unavailable") from None
        if reply is True:
            return
        if reply is None:
            raise AuthorizationError(ReasonCode.REPLAY_DETECTED, "operation already performed")
        _logger.warning("replay store returned an unexpected reply (%s)", type(reply).__name__)
        raise DependencyError("replay store returned an unexpected reply")

    def __repr__(self) -> str:
        return f"{type(self).__name__}(prefix={self._prefix!r})"

    def _ttl_ms(self, expires_at: float) -> int:
        # PyTraT profile: the TTL is relative and computed from the injected clock (the same
        # clock the verifier uses), so a Redis server whose clock is ahead cannot drop a record
        # early. Nonsensical expiries deny rather than record something meaningless.
        if not math.isfinite(expires_at):
            raise DependencyError("replay expiry is not a finite time")
        remaining = expires_at - self._clock.now()
        if remaining > self._max_ttl_seconds:
            raise DependencyError("replay expiry exceeds the configured maximum")
        retain = remaining + self._margin_seconds
        if retain <= 0:
            raise DependencyError("replay expiry is already in the past")
        return max(1, math.ceil(retain * 1000))

    def _redis_key(self, key: str) -> str:
        # surrogatepass: a txn decoded from JSON may hold lone surrogates; hashing must not fail
        # and must stay injective.
        digest = hashlib.sha256(key.encode("utf-8", "surrogatepass")).hexdigest()
        return f"{self._prefix}{digest}"
