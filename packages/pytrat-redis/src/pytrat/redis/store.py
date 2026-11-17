"""A :class:`~pytrat.core.replay.ReplayStore` shared by every instance through Redis.

txn-tokens-11 §13.1: Txn-Tokens are not resistant to replay. PyTraT profile P8 makes single-use
opt-in per operation; :class:`~pytrat.core.replay.InMemoryReplayStore` enforces it only within one
process. This store enforces it across every process that shares one Redis.

Each first use is a single atomic ``SET key 1 NX PX <ttl>``: Redis either creates the key (first
use) or leaves it untouched (replay). There is no read-then-write window in which two instances
can both observe "unused".

The guarantee holds only while Redis keeps every record until its TTL. A Redis that evicts keys
under memory pressure silently re-enables replay, so the server must run with
``maxmemory-policy noeviction`` (checked by :meth:`RedisReplayStore.verify_configuration`).
"""

from __future__ import annotations

import hashlib
import logging
import math
import ssl
from collections.abc import Mapping
from datetime import timedelta
from typing import Final, Protocol, Self
from urllib.parse import urlsplit

import redis
from redis.backoff import NoBackoff
from redis.connection import SSLConnection
from redis.exceptions import RedisError, ResponseError
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
_EVICTION_POLICY: Final = "maxmemory-policy"
_REQUIRED_EVICTION_POLICY: Final = "noeviction"
_MAX_REPORTED_POLICY_LENGTH: Final = 32
_TLS_SCHEME: Final = "rediss"
# Passed explicitly for rediss:// so certificate and hostname verification never depend on the
# redis-py version's defaults (5.x did not check hostnames).
_TLS_OPTIONS: Final = {"ssl_cert_reqs": "required", "ssl_check_hostname": True}


class RedisClient(Protocol):
    """The Redis commands this store needs. ``redis.Redis`` satisfies it.

    Must be a synchronous client: an asyncio client returns an awaitable, which the store treats
    as an unexpected reply and denies.
    """

    def set(self, name: str, value: str, *, nx: bool, px: int) -> object:
        """``SET name value NX PX px``; ``True`` if set, ``None`` if the key already existed."""
        ...

    def config_get(self, pattern: str) -> object:
        """``CONFIG GET pattern``; a mapping of parameter name to value."""
        ...


class RedisReplayStore:
    """Records first uses in Redis so every instance sharing it rejects a replay.

    Guarantees:

    * Atomic: one ``SET NX PX`` per call, so N concurrent callers on one key get exactly one
      success and N-1 ``REPLAY_DETECTED``, whichever instances they run on.
    * Fail closed: any Redis error, timeout or unexpected reply raises :class:`DependencyError`.
    * Keys are ``prefix + namespace + ":" + sha256(key)``; raw ``txn`` values never reach Redis,
      and neither keys nor connection URLs are logged.
    * Services sharing one Redis do not share records: each uses its own ``namespace``, so the
      same single-use operation id at two services is two independent records.
    * A record is kept until ``expires_at + retention_margin`` measured from the injected clock,
      so it outlives the verifier's ``exp`` leeway and does not depend on Redis's own clock.

    Records are only as durable as Redis keeps them: the server must use
    ``maxmemory-policy noeviction`` (call :meth:`verify_configuration` at startup) and its
    persistence and failover settings bound what a restart can forget.

    The store is synchronous. The FastAPI integration calls it on the event loop, so the client
    must have short socket timeouts; :meth:`from_url` configures them.

    Args:
        client: A synchronous Redis client (``redis.Redis``), already configured.
        namespace: The name of the service using the store (for example ``"ledger-service"``).
            Every instance of one service must use the same value and different services must
            use different values. Printable, no spaces, no ``:``.
        prefix: Key prefix, so several environments or applications can share one Redis.
        clock: Time source used to turn ``expires_at`` into a relative TTL.
        retention_margin: Extra time a record is kept past ``expires_at``. Must cover the
            verifier's ``leeway`` plus clock skew between instances. At most one hour.
        max_ttl: Largest accepted ``expires_at - now``. Longer requests are refused (deny), not
            truncated, because truncating would re-open replay before the token expires.

    Raises:
        ConfigurationError: If ``namespace``, ``prefix``, ``retention_margin`` or ``max_ttl`` is
            invalid.
    """

    __slots__ = (
        "_client",
        "_clock",
        "_key_prefix",
        "_margin_seconds",
        "_max_ttl_seconds",
        "_namespace",
        "_prefix",
    )

    def __init__(
        self,
        client: RedisClient,
        *,
        namespace: str,
        prefix: str = DEFAULT_PREFIX,
        clock: Clock | None = None,
        retention_margin: timedelta = _DEFAULT_RETENTION_MARGIN,
        max_ttl: timedelta = _DEFAULT_MAX_TTL,
    ) -> None:
        if not _is_key_text(prefix):
            raise ConfigurationError("replay key prefix must be non-empty printable text")
        # PyTraT profile: keys carry the service's namespace, otherwise a workload holding the
        # token could burn a single-use id at one service to deny it at another. ":" is
        # excluded so one namespace cannot reach into another's key space.
        if not _is_key_text(namespace) or ":" in namespace:
            raise ConfigurationError(
                "replay namespace must be non-empty printable text without spaces or ':'"
            )
        if not timedelta(0) <= retention_margin <= _MAX_RETENTION_MARGIN:
            raise ConfigurationError("retention_margin must be between 0 and 1 hour")
        if max_ttl <= timedelta(0):
            raise ConfigurationError("max_ttl must be positive")
        self._client = client
        self._prefix = prefix
        self._namespace = namespace
        self._key_prefix = f"{prefix}{namespace}:"
        self._clock: Clock = clock or SystemClock()
        self._margin_seconds = retention_margin.total_seconds()
        self._max_ttl_seconds = max_ttl.total_seconds()

    @classmethod
    def from_url(
        cls,
        url: str,
        *,
        namespace: str,
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

        For ``rediss://`` the client verifies the server certificate against the system trust
        store *and* checks that it names the URL's host. Without the hostname check, anyone with
        any publicly trusted certificate could answer ``OK`` to every ``SET NX`` and defeat
        single use. A URL whose querystring turns either check off is refused.

        Args:
            url: ``redis://``, ``rediss://`` or ``unix://`` URL. Prefer ``rediss://`` across a
                network.
            namespace: See :class:`RedisReplayStore`.
            prefix: See :class:`RedisReplayStore`.
            clock: See :class:`RedisReplayStore`.
            retention_margin: See :class:`RedisReplayStore`.
            max_ttl: See :class:`RedisReplayStore`.
            socket_timeout: Connect and command timeout in seconds.

        Raises:
            ConfigurationError: If the URL or any option is invalid, or the URL disables TLS
                certificate or hostname verification. The message never contains the URL, which
                may carry a password.
        """
        if not (math.isfinite(socket_timeout) and socket_timeout > 0):
            raise ConfigurationError("socket_timeout must be a positive number of seconds")
        try:
            # redis-py lowercases the scheme the same way before choosing SSLConnection; plain
            # connections reject ssl_* keyword arguments, so they are passed only for TLS.
            tls_options = _TLS_OPTIONS if urlsplit(url).scheme == _TLS_SCHEME else {}
            client = redis.Redis.from_url(
                url,
                socket_timeout=socket_timeout,
                socket_connect_timeout=socket_timeout,
                retry=Retry(NoBackoff(), 0),
                **tls_options,
            )
        except (ValueError, TypeError):
            raise ConfigurationError("invalid Redis URL") from None
        _require_verified_tls(client.connection_pool)
        return cls(
            client,
            namespace=namespace,
            prefix=prefix,
            clock=clock,
            retention_margin=retention_margin,
            max_ttl=max_ttl,
        )

    def verify_configuration(self) -> None:
        """Check that Redis will never evict a replay record before its TTL.

        Reads ``CONFIG GET maxmemory-policy`` and requires ``noeviction``. With any other policy,
        Redis under memory pressure silently deletes records and a replay is accepted; with
        ``noeviction`` a full Redis refuses the write instead, which this store turns into a
        deny. Call it at startup. It cannot detect a policy changed later at runtime.

        Managed Redis services often disable ``CONFIG``, in which case this raises
        :class:`ConfigurationError`; verify ``noeviction`` through the provider instead.

        Raises:
            ConfigurationError: If the policy is not ``noeviction``, cannot be read from the
                reply, or ``CONFIG`` is unavailable to this client.
            DependencyError: If Redis fails, times out or replies with something other than a
                mapping.
        """
        try:
            reply = self._client.config_get(_EVICTION_POLICY)
        except ResponseError:
            # Includes NoPermissionError (ACL). The error text is not echoed.
            raise ConfigurationError(
                "cannot read Redis maxmemory-policy (CONFIG is unavailable to this client); "
                "verify 'noeviction' out of band"
            ) from None
        except (RedisError, OSError) as exc:
            _logger.warning("replay store unavailable (%s)", type(exc).__name__)
            raise DependencyError("replay store is unavailable") from None
        if not isinstance(reply, Mapping):
            _logger.warning("replay store returned an unexpected reply (%s)", type(reply).__name__)
            raise DependencyError("replay store returned an unexpected reply")
        policy = _config_value(reply, _EVICTION_POLICY)
        if policy == _REQUIRED_EVICTION_POLICY:
            return
        if policy is None:
            raise ConfigurationError(
                "Redis did not report a readable maxmemory-policy; 'noeviction' is required"
            )
        raise ConfigurationError(
            f"Redis maxmemory-policy is {policy!r}; 'noeviction' is required so replay records "
            "are never evicted"
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
        return f"{type(self).__name__}(prefix={self._prefix!r}, namespace={self._namespace!r})"

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
        return f"{self._key_prefix}{digest}"


def _is_key_text(value: str) -> bool:
    return bool(value) and value.isprintable() and " " not in value


def _config_value(reply: Mapping[object, object], name: str) -> str | None:
    """The text value of ``name`` in a ``CONFIG GET`` reply (str or bytes), else ``None``."""
    raw_value = reply.get(name, reply.get(name.encode()))
    if isinstance(raw_value, bytes):
        try:
            raw_value = raw_value.decode("ascii")
        except UnicodeDecodeError:
            return None
    if not isinstance(raw_value, str) or len(raw_value) > _MAX_REPORTED_POLICY_LENGTH:
        return None
    return raw_value if raw_value.isprintable() else None


def _require_verified_tls(pool: redis.ConnectionPool) -> None:
    # redis-py lets URL querystring options override keyword arguments, so the built pool is
    # checked rather than trusted.
    if not issubclass(pool.connection_class, SSLConnection):
        return
    options = pool.connection_kwargs
    cert_reqs = options.get("ssl_cert_reqs")
    if (
        cert_reqs not in ("required", ssl.CERT_REQUIRED)
        or options.get("ssl_check_hostname") is not True
    ):
        raise ConfigurationError("Redis TLS must verify the server certificate and hostname")
