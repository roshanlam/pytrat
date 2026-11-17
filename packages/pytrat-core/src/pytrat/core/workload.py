"""Authentication of the calling workload at a resource service.

A Transaction Token says *what* was authorized; it never says *who is calling* (txn-tokens-11
§13.12). Resource services therefore authenticate the immediate caller independently, with one of
the framework-agnostic authenticators here. Framework integrations convert their request object
into an :class:`InboundRequest` and call :meth:`WorkloadAuthenticator.authenticate`.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Protocol, TypeGuard

from pytrat.core.clock import Clock, SystemClock
from pytrat.core.errors import AuthenticationError, ConfigurationError, ReasonCode, TokenError
from pytrat.core.jws import verify_jws
from pytrat.core.keys import KeyProvider

# WIMSE workload identity tokens use typ "wit+jwt"; plain "JWT" is accepted for interoperability.
WORKLOAD_JWT_TYPES: Final = frozenset({"wit+jwt", "jwt"})
DEFAULT_WORKLOAD_JWT_HEADER: Final = "Workload-Identity"


@dataclass(frozen=True, slots=True)
class WorkloadIdentity:
    """An authenticated calling workload.

    Attributes:
        id: Stable workload identifier (e.g. a SPIFFE ID or service name).
        method: How it was authenticated, for audit (``"workload-jwt"``, ``"mtls-proxy"``, ...).
    """

    id: str
    method: str


@dataclass(frozen=True, slots=True)
class InboundRequest:
    """The transport facts an authenticator may use. Header names are matched case-insensitively.

    Attributes:
        headers: Every header as ``(name, value)`` pairs, preserving duplicates.
        peer: The immediate peer's IP address, if known.
    """

    headers: Sequence[tuple[str, str]]
    peer: str | None = None

    @classmethod
    def from_mapping(cls, headers: Mapping[str, str], peer: str | None = None) -> InboundRequest:
        """Build from a single-valued header mapping."""
        return cls(tuple(headers.items()), peer)

    def values(self, name: str) -> list[str]:
        """All values of header ``name``."""
        lowered = name.lower()
        return [value for key, value in self.headers if key.lower() == lowered]

    def single(self, name: str) -> str | None:
        """The only value of header ``name``, or None if absent.

        Raises:
            TokenError: ``TOKEN_MALFORMED`` if the header appears more than once.
        """
        found = self.values(name)
        if len(found) > 1:
            raise TokenError(ReasonCode.TOKEN_MALFORMED, f"header {name} appears more than once")
        return found[0] if found else None


class WorkloadAuthenticator(Protocol):
    """Authenticates the calling workload from transport facts."""

    def authenticate(self, request: InboundRequest) -> WorkloadIdentity | None:
        """Return the caller's identity, or None if it presented no credential.

        Raises:
            AuthenticationError: ``WORKLOAD_UNAUTHENTICATED`` if a credential was presented but is
                invalid. An invalid credential is never treated as "no credential".
        """
        ...


class WorkloadJwtAuthenticator:
    """Verifies a signed workload JWT carried in a dedicated header.

    The JWT's ``sub`` is the workload id. It must be addressed to this service (``aud``), be
    short-lived, and be signed by a key in the trusted workload key set.
    """

    __slots__ = (
        "_algorithms",
        "_audience",
        "_clock",
        "_header",
        "_keys",
        "_leeway",
        "_max_lifetime",
    )

    def __init__(
        self,
        keys: KeyProvider,
        *,
        audience: str,
        algorithms: frozenset[str] = frozenset({"ES256", "EdDSA"}),
        header: str = DEFAULT_WORKLOAD_JWT_HEADER,
        max_lifetime: int = 300,
        leeway: int = 5,
        clock: Clock | None = None,
    ) -> None:
        if not audience:
            raise ConfigurationError("workload JWT audience must be set")
        self._keys = keys
        self._audience = audience
        self._algorithms = algorithms
        self._header = header
        self._max_lifetime = max_lifetime
        self._leeway = leeway
        self._clock: Clock = clock or SystemClock()

    def authenticate(self, request: InboundRequest) -> WorkloadIdentity | None:
        """Verify the workload JWT header if present."""
        try:
            raw = request.single(self._header)
        except TokenError:
            raise _unauthenticated("workload credential header repeated") from None
        if raw is None:
            return None
        try:
            payload = verify_jws(
                raw, self._keys, algorithms=self._algorithms, allowed_typ=WORKLOAD_JWT_TYPES
            ).payload
        except TokenError:
            raise _unauthenticated("workload credential failed verification") from None
        return WorkloadIdentity(id=self._check_claims(payload), method="workload-jwt")

    def _check_claims(self, payload: Mapping[str, object]) -> str:
        subject, audience = payload.get("sub"), payload.get("aud")
        iat, exp = payload.get("iat"), payload.get("exp")
        if not isinstance(subject, str) or not subject:
            raise _unauthenticated("workload credential has no subject")
        audiences = [audience] if isinstance(audience, str) else audience
        if not isinstance(audiences, list) or self._audience not in audiences:
            raise _unauthenticated("workload credential is not addressed to this service")
        if not _is_int(iat) or not _is_int(exp):
            raise _unauthenticated("workload credential lacks iat/exp")
        now = self._clock.now()
        if exp <= iat or exp - iat > self._max_lifetime:
            raise _unauthenticated("workload credential lifetime is invalid")
        if iat > now + self._leeway or now >= exp + self._leeway:
            raise _unauthenticated("workload credential is not currently valid")
        return subject


class TrustedProxyHeaderAuthenticator:
    """Reads a workload id set by a TLS-terminating proxy that verified the client certificate.

    The header is honoured only when the immediate peer is one of the trusted proxies; from any
    other peer it is an attack and is rejected rather than ignored.
    """

    __slots__ = ("_header", "_networks")

    def __init__(self, *, header: str, trusted_proxies: Iterable[str]) -> None:
        try:
            self._networks = tuple(ipaddress.ip_network(cidr) for cidr in trusted_proxies)
        except ValueError:
            raise ConfigurationError("trusted_proxies must be valid CIDR ranges") from None
        if not self._networks:
            raise ConfigurationError("at least one trusted proxy range is required")
        self._header = header

    def authenticate(self, request: InboundRequest) -> WorkloadIdentity | None:
        """Return the proxy-asserted identity if present and from a trusted proxy."""
        values = request.values(self._header)
        if not values:
            return None
        if len(values) > 1 or not values[0]:
            raise _unauthenticated("proxy identity header is malformed")
        if not self._from_trusted_proxy(request.peer):
            raise _unauthenticated("proxy identity header received from an untrusted peer")
        return WorkloadIdentity(id=values[0], method="mtls-proxy")

    def _from_trusted_proxy(self, peer: str | None) -> bool:
        if peer is None:
            return False
        try:
            address = ipaddress.ip_address(peer)
        except ValueError:
            return False
        return any(address in network for network in self._networks)


class FirstMatchAuthenticator:
    """Tries authenticators in order and returns the first identity found.

    An invalid credential from any authenticator stops the chain with an error.
    """

    __slots__ = ("_authenticators",)

    def __init__(self, *authenticators: WorkloadAuthenticator) -> None:
        if not authenticators:
            raise ConfigurationError("at least one authenticator is required")
        self._authenticators = authenticators

    def authenticate(self, request: InboundRequest) -> WorkloadIdentity | None:
        """Return the first identity any authenticator establishes."""
        for authenticator in self._authenticators:
            identity = authenticator.authenticate(request)
            if identity is not None:
                return identity
        return None


def _unauthenticated(detail: str) -> AuthenticationError:
    return AuthenticationError(ReasonCode.WORKLOAD_UNAUTHENTICATED, detail)


def _is_int(value: object) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)
