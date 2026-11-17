"""Remote JWKS refresh for verifiers (PyTraT profile P2).

txn-tokens-11 defines no key discovery, so the JWKS URL is pinned in trusted configuration. The
verify path never does I/O: :class:`RefreshingKeyProvider` holds an immutable
:class:`~pytrat.core.keys.StaticKeySet` that refreshers swap atomically. When refreshes keep failing
the last good set is used for at most ``max_stale``; after that every lookup fails closed.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from datetime import timedelta
from types import TracebackType
from typing import Final, Self

import httpx

from pytrat.client._transport import BoundedBody, require_secure_endpoint
from pytrat.core.clock import Clock, SystemClock
from pytrat.core.errors import ConfigurationError, DependencyError, ReasonCode, TokenError
from pytrat.core.keys import StaticKeySet, VerificationKey
from pytrat.core.validation import TokenVerifier, VerifiedToken

__all__ = [
    "MAX_JWKS_BYTES",
    "AsyncJwksRefresher",
    "JwksRefresher",
    "RefreshingKeyProvider",
    "parse_jwks",
    "verify_with_refresh",
    "verify_with_refresh_async",
]

_log = logging.getLogger(__name__)

#: Largest JWKS document accepted (matches the core parser's limit).
MAX_JWKS_BYTES: Final = 256 * 1024


def parse_jwks(data: bytes) -> StaticKeySet:
    """Parse a serialized JWKS into an immutable key set. Pure.

    Raises:
        ConfigurationError: ``KEY_UNKNOWN`` if the document is oversized, not strict JSON, empty,
            or contains any invalid, private or symmetric key.
    """
    if len(data) > MAX_JWKS_BYTES:
        raise ConfigurationError("JWKS document is too large", ReasonCode.KEY_UNKNOWN)
    keys = StaticKeySet.from_jwks_bytes(data)
    # PyTraT profile: an empty set is treated as a broken response, not as "trust nothing", so a
    # transient TTS fault does not instantly reject all traffic; max_stale still bounds it.
    if len(keys) == 0:
        raise ConfigurationError("JWKS contains no keys", ReasonCode.KEY_UNKNOWN)
    return keys


class RefreshingKeyProvider:
    """A :class:`~pytrat.core.keys.KeyProvider` whose key set is replaced atomically.

    ``get`` performs no I/O. It returns None (so verification fails with ``KEY_UNKNOWN``) when no
    set has been installed or when the installed set is older than ``max_stale``.
    """

    __slots__ = ("_clock", "_max_stale", "_snapshot")

    def __init__(self, clock: Clock, max_stale: timedelta) -> None:
        if max_stale <= timedelta(0):
            raise ConfigurationError("max_stale must be positive")
        self._clock = clock
        self._max_stale = max_stale.total_seconds()
        # One tuple, replaced by a single assignment, so readers never see a torn update.
        self._snapshot: tuple[StaticKeySet, float] | None = None

    def install(self, keys: StaticKeySet) -> None:
        """Atomically replace the key set and mark it fresh."""
        self._snapshot = (keys, self._clock.now())

    def age(self) -> float | None:
        """Seconds since the current set was installed, or None if there is none."""
        snapshot = self._snapshot
        return None if snapshot is None else self._clock.now() - snapshot[1]

    @property
    def key_set(self) -> StaticKeySet | None:
        """The current set if it is still usable, else None."""
        snapshot = self._snapshot
        if snapshot is None or self._clock.now() - snapshot[1] > self._max_stale:
            return None
        return snapshot[0]

    def get(self, kid: str | None) -> VerificationKey | None:
        """Return the trusted key for ``kid``; None if unknown or the set is too stale."""
        keys = self.key_set
        return None if keys is None else keys.get(kid)

    def __repr__(self) -> str:
        snapshot = self._snapshot
        kids = sorted(snapshot[0].kids) if snapshot is not None else []
        return f"RefreshingKeyProvider(kids={kids})"


class _RefreshCore:
    """Scheduling decisions and response handling shared by both refreshers."""

    __slots__ = (
        "_clock",
        "_completed",
        "_in_flight",
        "_keys",
        "_last_attempt",
        "_min_interval",
        "_timeout",
        "_ttl",
        "_url",
    )

    def __init__(
        self,
        jwks_url: str,
        *,
        clock: Clock | None,
        ttl: timedelta,
        max_stale: timedelta,
        min_refresh_interval: timedelta,
        timeout: float,
        allow_insecure_localhost: bool,
    ) -> None:
        self._url = require_secure_endpoint(
            jwks_url, allow_insecure_localhost=allow_insecure_localhost, what="jwks_url"
        )
        if ttl <= timedelta(0):
            raise ConfigurationError("ttl must be positive")
        if max_stale < ttl:
            raise ConfigurationError("max_stale must be at least ttl")
        if min_refresh_interval <= timedelta(0):
            raise ConfigurationError("min_refresh_interval must be positive")
        if timeout <= 0:
            raise ConfigurationError("timeout must be positive")
        self._clock: Clock = clock or SystemClock()
        self._keys = RefreshingKeyProvider(self._clock, max_stale)
        self._ttl = ttl.total_seconds()
        self._min_interval = min_refresh_interval.total_seconds()
        self._timeout = timeout
        self._last_attempt: float | None = None
        self._in_flight = False
        self._completed = 0

    @property
    def keys(self) -> RefreshingKeyProvider:
        """The key provider to hand to :class:`~pytrat.core.validation.TokenVerifier`."""
        return self._keys

    def _should_fetch(self, force: bool) -> bool:
        now = self._clock.now()
        # Rate limit every attempt, forced or not, so neither an unknown-kid storm nor a failing
        # TTS can turn into a flood of JWKS requests.
        if self._last_attempt is not None and now - self._last_attempt < self._min_interval:
            return False
        if force:
            return True
        age = self._keys.age()
        return age is None or age >= self._ttl

    def _must_wait(self, force: bool) -> bool:
        # A caller arriving while a fetch is in flight waits for it rather than failing closed.
        return self._in_flight or self._should_fetch(force)

    def _begin(self) -> None:
        self._last_attempt = self._clock.now()
        self._in_flight = True

    def _end(self) -> None:
        self._in_flight = False
        self._completed += 1

    def _complete(self, status: int, body: BoundedBody) -> None:
        if body.exceeded:
            _log.warning("JWKS refresh failed: response exceeds the size limit")
            return
        if status != 200:
            _log.warning("JWKS refresh failed: HTTP %d", status)
            return
        try:
            keys = parse_jwks(body.value())
        except ConfigurationError as exc:
            _log.warning("JWKS refresh failed: %s", exc.detail)
            return
        self._keys.install(keys)

    @staticmethod
    def _failed_transport() -> None:
        _log.warning("JWKS refresh failed: endpoint unreachable")

    def _result(self, before: StaticKeySet | None) -> bool:
        current = self._keys.key_set
        if current is None:
            # Fail closed: no set, or the last good set is older than max_stale.
            raise DependencyError("no usable JWKS is available")
        return current is not before

    def __repr__(self) -> str:
        return f"{type(self).__name__}(jwks_url={str(self._url)!r})"


class JwksRefresher(_RefreshCore):
    """Synchronous JWKS refresher. Thread-safe and single-flight.

    Call :meth:`refresh` at startup and on a schedule; use :func:`verify_with_refresh` to handle
    key rotation on unknown ``kid``.
    """

    __slots__ = ("_http", "_lock", "_owns_http")

    def __init__(
        self,
        jwks_url: str,
        *,
        clock: Clock | None = None,
        ttl: timedelta = timedelta(minutes=5),
        max_stale: timedelta = timedelta(minutes=30),
        min_refresh_interval: timedelta = timedelta(seconds=30),
        http_client: httpx.Client | None = None,
        timeout: float = 5.0,
        allow_insecure_localhost: bool = False,
    ) -> None:
        super().__init__(
            jwks_url,
            clock=clock,
            ttl=ttl,
            max_stale=max_stale,
            min_refresh_interval=min_refresh_interval,
            timeout=timeout,
            allow_insecure_localhost=allow_insecure_localhost,
        )
        self._lock = threading.Lock()
        self._owns_http = http_client is None
        self._http = http_client or httpx.Client(timeout=timeout, follow_redirects=False)

    def refresh(self, *, force: bool = False) -> bool:
        """Fetch the JWKS if the TTL has lapsed (or ``force``), subject to the rate limit.

        Returns:
            True if the usable key set changed during this call.

        Raises:
            DependencyError: ``DEPENDENCY_UNAVAILABLE`` if afterwards no usable set exists.
        """
        before = self._keys.key_set
        if self._must_wait(force):
            completed = self._completed
            with self._lock:
                # Single-flight: if a fetch finished while we waited, use its result.
                if self._completed == completed and self._should_fetch(force):
                    self._begin()
                    try:
                        self._fetch()
                    finally:
                        self._end()
        return self._result(before)

    def _fetch(self) -> None:
        body = BoundedBody(MAX_JWKS_BYTES)
        try:
            with self._http.stream(
                "GET",
                self._url,
                headers={"Accept": "application/json"},
                timeout=self._timeout,
                follow_redirects=False,
            ) as response:
                for chunk in response.iter_bytes():
                    if not body.feed(chunk):
                        break
        except httpx.HTTPError:
            self._failed_transport()
            return
        self._complete(response.status_code, body)

    def close(self) -> None:
        """Close the underlying HTTP client if this instance created it."""
        if self._owns_http:
            self._http.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


class AsyncJwksRefresher(_RefreshCore):
    """Asynchronous JWKS refresher. Single-flight within one event loop."""

    __slots__ = ("_http", "_lock", "_owns_http")

    def __init__(
        self,
        jwks_url: str,
        *,
        clock: Clock | None = None,
        ttl: timedelta = timedelta(minutes=5),
        max_stale: timedelta = timedelta(minutes=30),
        min_refresh_interval: timedelta = timedelta(seconds=30),
        http_client: httpx.AsyncClient | None = None,
        timeout: float = 5.0,
        allow_insecure_localhost: bool = False,
    ) -> None:
        super().__init__(
            jwks_url,
            clock=clock,
            ttl=ttl,
            max_stale=max_stale,
            min_refresh_interval=min_refresh_interval,
            timeout=timeout,
            allow_insecure_localhost=allow_insecure_localhost,
        )
        self._lock = asyncio.Lock()
        self._owns_http = http_client is None
        self._http = http_client or httpx.AsyncClient(timeout=timeout, follow_redirects=False)

    async def refresh(self, *, force: bool = False) -> bool:
        """Async variant of :meth:`JwksRefresher.refresh`."""
        before = self._keys.key_set
        if self._must_wait(force):
            completed = self._completed
            async with self._lock:
                if self._completed == completed and self._should_fetch(force):
                    self._begin()
                    try:
                        await self._fetch()
                    finally:
                        self._end()
        return self._result(before)

    async def _fetch(self) -> None:
        body = BoundedBody(MAX_JWKS_BYTES)
        try:
            async with self._http.stream(
                "GET",
                self._url,
                headers={"Accept": "application/json"},
                timeout=self._timeout,
                follow_redirects=False,
            ) as response:
                async for chunk in response.aiter_bytes():
                    if not body.feed(chunk):
                        break
        except httpx.HTTPError:
            self._failed_transport()
            return
        self._complete(response.status_code, body)

    async def aclose(self) -> None:
        """Close the underlying HTTP client if this instance created it."""
        if self._owns_http:
            await self._http.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()


def verify_with_refresh(
    verifier: TokenVerifier, refresher: JwksRefresher, raw_token: str
) -> VerifiedToken:
    """Verify ``raw_token``; on ``KEY_UNKNOWN`` force one rate-limited refresh and retry once.

    ``verifier`` must use ``refresher.keys`` as its key provider.

    Raises:
        TokenError: From verification (the original error if no new keys could be fetched).
        DependencyError: If no usable JWKS is available at all.
    """
    try:
        return verifier.verify(raw_token)
    except TokenError as exc:
        if exc.reason is not ReasonCode.KEY_UNKNOWN or not refresher.refresh(force=True):
            raise
    return verifier.verify(raw_token)


async def verify_with_refresh_async(
    verifier: TokenVerifier, refresher: AsyncJwksRefresher, raw_token: str
) -> VerifiedToken:
    """Async variant of :func:`verify_with_refresh`."""
    try:
        return verifier.verify(raw_token)
    except TokenError as exc:
        if exc.reason is not ReasonCode.KEY_UNKNOWN or not await refresher.refresh(force=True):
            raise
    return verifier.verify(raw_token)
