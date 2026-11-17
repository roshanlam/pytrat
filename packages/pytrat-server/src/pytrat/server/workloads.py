"""Workload authentication at the token endpoint (txn-tokens-11 §11.5).

txn-tokens-11 §11.5: "A TTS MUST authenticate a workload to ensure the workload is authorized to
request a transaction token." Every failure here is ``invalid_client`` (HTTP 401). A Txn-Token is
never accepted as a workload credential (txn-tokens-11 §13.12).

Two adapters are provided:

* :class:`PrivateKeyJwtAuthenticator`: RFC 7523 ``private_key_jwt`` client assertions verified
  against each workload's registered public keys, with single-use ``jti``.
* :class:`TrustedProxyMtlsAuthenticator`: a workload identity asserted by a TLS-terminating proxy
  in a header, honoured only when the TCP peer is a configured trusted proxy.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Protocol, Self

from pytrat.core.clock import Clock
from pytrat.core.constants import CLIENT_ASSERTION_TYPE_JWT_BEARER
from pytrat.core.errors import (
    AuthorizationError,
    ConfigurationError,
    PyTraTError,
    ReasonCode,
    TokenError,
)
from pytrat.core.jws import verify_jws
from pytrat.core.keys import KeyProvider, StaticKeySet, VerificationKey
from pytrat.core.replay import ReplayStore
from pytrat.server.errors import OAuthError, OAuthErrorCode, translate
from pytrat.server.forms import TokenRequest
from pytrat.server.settings import TrustedProxyConfig, TtsSettings

__all__ = [
    "CompositeAuthenticator",
    "CredentialsAbsentError",
    "Headers",
    "PrivateKeyJwtAuthenticator",
    "TrustedProxyMtlsAuthenticator",
    "WorkloadAuthenticator",
    "WorkloadIdentity",
    "WorkloadRegistry",
]

type Headers = Mapping[str, Sequence[str]]
"""Request headers: lower-cased name to every value received for it."""

_MAX_ASSERTION_BYTES: Final = 8192
_MAX_JTI_LENGTH: Final = 256


@dataclass(frozen=True, slots=True)
class WorkloadIdentity:
    """An authenticated, registered workload."""

    id: str


class WorkloadAuthenticator(Protocol):
    """Establishes which registered workload sent a token request."""

    def authenticate(
        self, request: TokenRequest, headers: Headers, peer: str | None
    ) -> WorkloadIdentity:
        """Authenticate the requester.

        Raises:
            CredentialsAbsentError: If this method's credentials are not present at all.
            OAuthError: ``invalid_client`` if credentials are present but invalid.
        """
        ...


class CredentialsAbsentError(OAuthError):
    """The request carries no credentials for this authentication method."""

    def __init__(self, description: str = "no client authentication was presented") -> None:
        super().__init__(
            OAuthErrorCode.INVALID_CLIENT, description, ReasonCode.WORKLOAD_UNAUTHENTICATED
        )


def _unauthenticated(
    description: str, reason: ReasonCode = ReasonCode.WORKLOAD_UNAUTHENTICATED
) -> OAuthError:
    return OAuthError(OAuthErrorCode.INVALID_CLIENT, description, reason)


class _OwnedKeys:
    """A key provider over every workload key, remembering which workload owns each ``kid``."""

    __slots__ = ("_keys", "_owner")

    def __init__(self, keys: Mapping[str, VerificationKey], owner: Mapping[str, str]) -> None:
        self._keys = keys
        self._owner = owner

    def get(self, kid: str | None) -> VerificationKey | None:
        # kid is always required for client assertions; never fall back to "the only key".
        return None if kid is None else self._keys.get(kid)

    def owner_of(self, kid: str) -> str:
        return self._owner[kid]


class WorkloadRegistry:
    """Registered workloads and their trusted public keys. Immutable after construction."""

    __slots__ = ("_by_kid", "_keys")

    def __init__(self, workloads: Mapping[str, StaticKeySet]) -> None:
        """Index ``workloads`` (workload id to its public keys).

        Raises:
            ConfigurationError: If two workloads share a ``kid`` (the ``kid`` alone must identify
                the owning workload) or an id is empty or contains ``,`` (PyTraT profile P5).
        """
        keys: dict[str, VerificationKey] = {}
        owner: dict[str, str] = {}
        for workload_id, key_set in workloads.items():
            if not workload_id or "," in workload_id:
                raise ConfigurationError("workload id must be non-empty and must not contain ','")
            for kid in key_set.kids:
                if kid in keys:
                    raise ConfigurationError("a kid is registered for more than one workload")
                key = key_set.get(kid)
                assert key is not None  # noqa: S101 - kid comes from the same set
                keys[kid] = key
                owner[kid] = workload_id
        self._keys: Mapping[str, StaticKeySet] = MappingProxyType(dict(workloads))
        self._by_kid = _OwnedKeys(MappingProxyType(keys), MappingProxyType(owner))

    @classmethod
    def from_settings(cls, settings: TtsSettings) -> Self:
        """Load every workload's JWKS from configuration.

        Raises:
            ConfigurationError: If a JWKS is missing or invalid.
        """
        workloads: dict[str, StaticKeySet] = {}
        for workload in settings.workloads:
            if workload.jwks_path is not None:
                workloads[workload.id] = StaticKeySet.from_jwks_file(workload.jwks_path)
            else:
                assert workload.jwks is not None  # noqa: S101 - enforced by the settings model
                workloads[workload.id] = StaticKeySet.from_jwks(workload.jwks)
        return cls(workloads)

    def is_registered(self, workload_id: str) -> bool:
        """Return True if ``workload_id`` is registered."""
        return workload_id in self._keys

    def keys_for(self, workload_id: str) -> StaticKeySet | None:
        """Return the public keys of ``workload_id``."""
        return self._keys.get(workload_id)

    @property
    def all_keys(self) -> KeyProvider:
        """A key provider over every registered workload key, selected by ``kid``."""
        return self._by_kid

    def owner_of(self, kid: str) -> str:
        """Return the workload that registered ``kid``."""
        return self._by_kid.owner_of(kid)


def _audience_matches(aud: object, expected: str) -> bool:
    if isinstance(aud, str):
        return aud == expected
    return isinstance(aud, list) and expected in aud and all(isinstance(a, str) for a in aud)


def _int_claim(payload: Mapping[str, object], name: str) -> int | None:
    value = payload.get(name)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise _unauthenticated(f"assertion claim '{name}' must be an integer")
    return value


class PrivateKeyJwtAuthenticator:
    """RFC 7523 ``private_key_jwt`` client authentication.

    The assertion's ``kid`` selects a trusted key from the registry, which also identifies the
    owning workload; the assertion payload is never read before its signature is verified.
    """

    __slots__ = (
        "_algorithms",
        "_clock",
        "_leeway",
        "_max_lifetime",
        "_registry",
        "_replay",
        "_token_endpoint",
    )

    def __init__(
        self,
        registry: WorkloadRegistry,
        *,
        token_endpoint: str,
        algorithms: frozenset[str],
        replay_store: ReplayStore,
        clock: Clock,
        leeway_seconds: int = 5,
        max_lifetime_seconds: int = 300,
    ) -> None:
        self._registry = registry
        self._token_endpoint = token_endpoint
        self._algorithms = algorithms
        self._replay = replay_store
        self._clock = clock
        self._leeway = leeway_seconds
        self._max_lifetime = max_lifetime_seconds

    def authenticate(
        self, request: TokenRequest, headers: Headers, peer: str | None
    ) -> WorkloadIdentity:
        """Verify the client assertion; see :class:`WorkloadAuthenticator`."""
        client = request.client
        if client.client_assertion is None and client.client_assertion_type is None:
            raise CredentialsAbsentError()
        if client.client_assertion_type != CLIENT_ASSERTION_TYPE_JWT_BEARER:
            raise _unauthenticated("client_assertion_type must be jwt-bearer")
        if client.client_assertion is None:
            raise _unauthenticated("client_assertion is required")
        try:
            verified = verify_jws(
                client.client_assertion.reveal(),
                self._registry.all_keys,
                algorithms=self._algorithms,
                allowed_typ=None,
                require_kid=True,
                max_bytes=_MAX_ASSERTION_BYTES,
            )
        except TokenError as exc:
            raise _unauthenticated(f"client assertion rejected: {exc.detail}") from None
        workload_id = self._registry.owner_of(verified.key.kid)
        self._check_claims(verified.payload, workload_id, client.client_id)
        return WorkloadIdentity(workload_id)

    def _check_claims(
        self, payload: Mapping[str, object], workload_id: str, client_id: str | None
    ) -> None:
        # RFC 7523 §3: iss and sub MUST both identify the client.
        if payload.get("iss") != workload_id or payload.get("sub") != workload_id:
            raise _unauthenticated("assertion iss and sub must identify the signing workload")
        if client_id is not None and client_id != workload_id:
            raise _unauthenticated("client_id does not match the client assertion")
        # RFC 7523 §3: aud MUST identify the authorization server (its token endpoint).
        if not _audience_matches(payload.get("aud"), self._token_endpoint):
            raise _unauthenticated("assertion aud is not this token endpoint")
        expires_at = self._check_times(payload)
        jti = payload.get("jti")
        if not isinstance(jti, str) or not jti or len(jti) > _MAX_JTI_LENGTH:
            raise _unauthenticated("assertion jti is required")
        try:
            # RFC 7523 §3: jti MAY be used for replay protection; PyTraT profile: always single-use.
            self._replay.record_once(
                f"client-assertion|{len(workload_id)}:{workload_id}|{jti}",
                float(expires_at + self._leeway),
            )
        except AuthorizationError:
            raise _unauthenticated(
                "client assertion was already used", ReasonCode.REPLAY_DETECTED
            ) from None
        except PyTraTError as exc:
            raise translate(exc, OAuthErrorCode.INVALID_CLIENT) from None

    def _check_times(self, payload: Mapping[str, object]) -> int:
        now = self._clock.now()
        expires_at = _int_claim(payload, "exp")
        # RFC 7523 §3: exp is required and the assertion MUST be rejected once expired.
        if expires_at is None:
            raise _unauthenticated("assertion exp is required")
        if now >= expires_at + self._leeway:
            raise _unauthenticated("client assertion has expired")
        # PyTraT profile: assertions are short-lived, which also bounds the jti replay window.
        if expires_at > now + self._max_lifetime + self._leeway:
            raise _unauthenticated("client assertion lifetime is too long")
        for name in ("iat", "nbf"):
            value = _int_claim(payload, name)
            if value is not None and value > now + self._leeway:
                raise _unauthenticated(f"assertion {name} is in the future")
        return expires_at


class TrustedProxyMtlsAuthenticator:
    """Workload identity from a TLS-terminating proxy header.

    The header is honoured only when the TCP peer address is inside a configured trusted-proxy
    CIDR. A header received from any other peer is an attack, not an absence of credentials.
    """

    __slots__ = ("_header", "_networks", "_registry")

    def __init__(self, config: TrustedProxyConfig, registry: WorkloadRegistry) -> None:
        self._header = config.header.lower()
        self._networks = tuple(ipaddress.ip_network(cidr) for cidr in config.trusted_cidrs)
        self._registry = registry

    def authenticate(
        self, request: TokenRequest, headers: Headers, peer: str | None
    ) -> WorkloadIdentity:
        """Authenticate from the proxy header; see :class:`WorkloadAuthenticator`."""
        values = headers.get(self._header, ())
        if not values:
            raise CredentialsAbsentError()
        if not self._peer_is_trusted(peer):
            raise _unauthenticated("workload identity header received from an untrusted peer")
        if len(values) != 1 or not values[0]:
            raise _unauthenticated("workload identity header must appear exactly once")
        workload_id = values[0]
        if not self._registry.is_registered(workload_id):
            raise _unauthenticated("workload is not registered")
        client_id = request.client.client_id
        if client_id is not None and client_id != workload_id:
            raise _unauthenticated("client_id does not match the authenticated workload")
        return WorkloadIdentity(workload_id)

    def _peer_is_trusted(self, peer: str | None) -> bool:
        if peer is None:
            return False
        try:
            address = ipaddress.ip_address(peer)
        except ValueError:
            return False
        return any(address in network for network in self._networks)


class CompositeAuthenticator:
    """Tries several authentication methods; exactly one must present credentials.

    A method whose credentials are present but invalid fails the request immediately: there is
    no fallback to another, possibly weaker, method. Presenting credentials for more than one
    method is rejected (RFC 6749 §2.3: a client MUST NOT use more than one method per request).
    """

    __slots__ = ("_authenticators",)

    def __init__(self, authenticators: Iterable[WorkloadAuthenticator]) -> None:
        self._authenticators = tuple(authenticators)
        if not self._authenticators:
            raise ValueError("at least one authenticator is required")

    def authenticate(
        self, request: TokenRequest, headers: Headers, peer: str | None
    ) -> WorkloadIdentity:
        """Authenticate with the single method the request uses."""
        identities: list[WorkloadIdentity] = []
        for authenticator in self._authenticators:
            try:
                identities.append(authenticator.authenticate(request, headers, peer))
            except CredentialsAbsentError:
                continue
        if not identities:
            raise CredentialsAbsentError()
        if len(identities) > 1:
            raise _unauthenticated("more than one client authentication method was used")
        return identities[0]
