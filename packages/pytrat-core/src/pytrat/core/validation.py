"""Transaction Token verification.

:class:`TokenVerifier` turns an untrusted string into a :class:`VerifiedToken` or raises a
:class:`~pytrat.core.errors.TokenError` with a specific reason. It performs no I/O: keys come from
an in-memory :class:`~pytrat.core.keys.KeyProvider`, time from an injected
:class:`~pytrat.core.clock.Clock`.

Check order is fixed (and tested), so a given bad token always yields the same reason:

1. size and compact-JWS shape
2. header: ``typ``, ``alg`` allowlist, forbidden parameters, ``kid``
3. trusted key lookup and key/algorithm compatibility
4. signature
5. claim types and presence
6. Trust Domain (``aud``) and issuer
7. time: ``iat``, ``exp``, maximum lifetime
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Final

from pytrat.core.claims import TransactionClaims, parse_claims
from pytrat.core.clock import Clock, SystemClock
from pytrat.core.constants import DEFAULT_ALGORITHMS, FORBIDDEN_ALGORITHMS, SUPPORTED_ALGORITHMS
from pytrat.core.errors import ConfigurationError, ReasonCode, TokenError
from pytrat.core.jws import verify_jws
from pytrat.core.keys import KeyProvider, VerificationKey
from pytrat.core.secret import SecretToken

# The largest clock-skew leeway a verifier may be configured with; replay records outlive it.
MAX_LEEWAY: Final = timedelta(seconds=60)
_SEAL: Final = object()


@dataclass(frozen=True, slots=True)
class VerifierSettings:
    """Verification policy for one Trust Domain. Validated on construction.

    Attributes:
        trust_domain: The only ``aud`` value accepted (txn-tokens-11 §12.2).
        algorithms: Accepted JWS algorithms. ``none`` and ``HS*`` can never be enabled.
        expected_issuer: If set, ``iss`` is required and must match (PyTraT profile P7).
        max_lifetime: Maximum ``exp - iat`` (PyTraT profile P3).
        leeway: Clock skew tolerance for ``iat`` and ``exp``; at most 60 seconds.
        require_kid: Reject tokens without a ``kid`` header (PyTraT profile P2).
        max_token_bytes: Reject larger tokens before any parsing.
        cache_size: Number of verified tokens to cache by digest; 0 disables caching.
    """

    trust_domain: str
    algorithms: frozenset[str] = DEFAULT_ALGORITHMS
    expected_issuer: str | None = None
    max_lifetime: timedelta = timedelta(minutes=5)
    leeway: timedelta = timedelta(seconds=5)
    require_kid: bool = True
    max_token_bytes: int = 16_384
    cache_size: int = 0

    def __post_init__(self) -> None:
        if not self.trust_domain:
            raise ConfigurationError("trust_domain must be set")
        if not self.algorithms:
            raise ConfigurationError("at least one algorithm must be allowed")
        if forbidden := self.algorithms & FORBIDDEN_ALGORITHMS:
            raise ConfigurationError(f"algorithms {sorted(forbidden)} can never be enabled")
        if unknown := self.algorithms - SUPPORTED_ALGORITHMS:
            raise ConfigurationError(f"unsupported algorithms {sorted(unknown)}")
        if self.max_lifetime <= timedelta(0):
            raise ConfigurationError("max_lifetime must be positive")
        if not timedelta(0) <= self.leeway <= MAX_LEEWAY:
            raise ConfigurationError("leeway must be between 0 and 60 seconds")
        if self.max_token_bytes < 256:
            raise ConfigurationError("max_token_bytes is unreasonably small")
        if self.cache_size < 0:
            raise ConfigurationError("cache_size must not be negative")


@dataclass(frozen=True, slots=True)
class VerifiedToken:
    """A Transaction Token whose signature, Trust Domain and lifetime have been verified.

    Instances can only be created by :class:`TokenVerifier`; holding one is proof of verification.

    Attributes:
        claims: The verified claims.
        forwardable: The original token, for unchanged propagation only (txn-tokens-11 §12.2).
        kid: Identifier of the key that verified it.
        alg: Algorithm that verified it.
    """

    claims: TransactionClaims
    forwardable: SecretToken = field(repr=False)
    kid: str
    alg: str
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SEAL:
            raise TypeError("VerifiedToken can only be created by TokenVerifier")

    @property
    def digest(self) -> str:
        """SHA-256 of the token; the only form of the token that may be logged."""
        return self.forwardable.digest

    @property
    def id(self) -> str:
        """The transaction identifier (``txn``)."""
        return self.claims.txn


@dataclass(slots=True)
class _CacheEntry:
    token: VerifiedToken
    key: VerificationKey


class TokenVerifier:
    """Verifies Transaction Tokens for one Trust Domain.

    Thread-safe. ``verify`` is CPU-only and suitable for both sync and async code.
    """

    __slots__ = ("_cache", "_clock", "_keys", "_lock", "_settings")

    def __init__(
        self, settings: VerifierSettings, keys: KeyProvider, clock: Clock | None = None
    ) -> None:
        self._settings = settings
        self._keys = keys
        self._clock: Clock = clock or SystemClock()
        self._cache: OrderedDict[str, _CacheEntry] = OrderedDict()
        self._lock = threading.Lock()

    @property
    def settings(self) -> VerifierSettings:
        """The verification policy."""
        return self._settings

    def verify(self, raw_token: str) -> VerifiedToken:
        """Verify an untrusted token string.

        Raises:
            TokenError: With the reason for the first failed check.
        """
        settings = self._settings
        if settings.cache_size and len(raw_token) <= settings.max_token_bytes:
            cached = self._cached(raw_token)
            if cached is not None:
                return cached

        verified = verify_jws(
            raw_token,
            self._keys,
            algorithms=settings.algorithms,
            require_kid=settings.require_kid,
            max_bytes=settings.max_token_bytes,
        )
        key, payload = verified.key, verified.payload
        claims = parse_claims(payload)
        self._check_claims(claims)

        token = VerifiedToken(
            claims=claims,
            forwardable=SecretToken(raw_token),
            kid=key.kid,
            alg=verified.alg,
            _seal=_SEAL,
        )
        if settings.cache_size:
            self._store(token, key)
        return token

    def _check_claims(self, claims: TransactionClaims) -> None:
        settings = self._settings
        # txn-tokens-11 §12.2: aud MUST identify this workload's Trust Domain.
        if claims.aud != settings.trust_domain:
            raise TokenError(ReasonCode.TRUST_DOMAIN_MISMATCH, "aud is not this Trust Domain")
        # PyTraT profile P7: issuer is checked only when configured, but then it is mandatory.
        if settings.expected_issuer is not None and claims.iss != settings.expected_issuer:
            raise TokenError(ReasonCode.ISSUER_MISMATCH, "iss is not the expected issuer")
        self._check_time(claims)

    def _check_time(self, claims: TransactionClaims) -> None:
        settings = self._settings
        now = self._clock.now()
        leeway = settings.leeway.total_seconds()
        if claims.exp <= claims.iat:
            raise TokenError(ReasonCode.CLAIM_INVALID, "exp is not after iat")
        # PyTraT profile P3: lifetime is "on the order of minutes or less" (txn-tokens-11 §6).
        if claims.exp - claims.iat > settings.max_lifetime.total_seconds():
            raise TokenError(ReasonCode.LIFETIME_EXCEEDED, "token lifetime exceeds the maximum")
        if claims.iat > now + leeway:
            raise TokenError(ReasonCode.TOKEN_NOT_YET_VALID, "iat is in the future")
        # txn-tokens-11 §12.2: the token MUST NOT be expired.
        if now >= claims.exp + leeway:
            raise TokenError(ReasonCode.TOKEN_EXPIRED, "token has expired")

    def _cached(self, raw_token: str) -> VerifiedToken | None:
        candidate = SecretToken(raw_token)
        with self._lock:
            entry = self._cache.get(candidate.digest)
            if entry is not None:
                self._cache.move_to_end(candidate.digest)
        if entry is None or entry.token.forwardable != candidate:
            return None
        # The key may have been removed or rotated since; a cache hit never outlives trust.
        if self._keys.get(entry.token.kid) is not entry.key:
            with self._lock:
                self._cache.pop(candidate.digest, None)
            return None
        try:
            self._check_time(entry.token.claims)
        except TokenError:
            with self._lock:
                self._cache.pop(candidate.digest, None)
            raise
        return entry.token

    def _store(self, token: VerifiedToken, key: VerificationKey) -> None:
        with self._lock:
            self._cache[token.digest] = _CacheEntry(token=token, key=key)
            self._cache.move_to_end(token.digest)
            while len(self._cache) > self._settings.cache_size:
                self._cache.popitem(last=False)
