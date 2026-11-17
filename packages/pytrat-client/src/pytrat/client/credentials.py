"""Workload credentials that authenticate a workload to the Transaction Token Service.

txn-tokens-11 §11.5: the TTS and the requesting workload MUST mutually authenticate. These
credentials add client authentication to an :class:`~pytrat.client.exchange.ExchangeRequest`;
server authentication is ordinary TLS verification in the transport.
"""

from __future__ import annotations

import secrets
import ssl
from pathlib import Path
from typing import Final, Protocol, runtime_checkable

from pytrat.client.exchange import ExchangeRequest
from pytrat.core.clock import Clock, SystemClock
from pytrat.core.constants import CLIENT_ASSERTION_TYPE_JWT_BEARER, FORBIDDEN_ALGORITHMS
from pytrat.core.crypto import algorithms_for_key, load_private_key_pem, sign_compact
from pytrat.core.errors import ConfigurationError, DependencyError

__all__ = [
    "MtlsCredential",
    "PrivateKeyJwtCredential",
    "SpiffeJwtSvidCredential",
    "WorkloadCredential",
]

# RFC 7523 §3 leaves lifetime to the profile. PyTraT profile: assertions live at most 60 seconds.
_MAX_ASSERTION_LIFETIME: Final = 60
_ASSERTION_TYP: Final = "JWT"
_MAX_SVID_BYTES: Final = 16 * 1024


@runtime_checkable
class WorkloadCredential(Protocol):
    """Adds workload authentication to a token-endpoint request."""

    def apply(self, request: ExchangeRequest) -> ExchangeRequest:
        """Return ``request`` with client-authentication parameters added.

        Raises:
            DependencyError: If the credential material is unavailable.
        """
        ...


def _require_non_empty(value: str, name: str) -> None:
    if not value:
        raise ConfigurationError(f"{name} must be a non-empty string")


class PrivateKeyJwtCredential:
    """RFC 7523 ``private_key_jwt`` client authentication.

    Each request carries a fresh, short-lived assertion with a unique ``jti``. The private key is
    loaded once from a file path; inline key strings are deliberately not accepted, so keys never
    sit in configuration objects or environment dumps.
    """

    __slots__ = ("_alg", "_client_id", "_clock", "_key", "_kid", "_lifetime", "_token_endpoint")

    def __init__(
        self,
        client_id: str,
        private_key_path: str | Path,
        *,
        alg: str,
        kid: str | None,
        token_endpoint: str,
        clock: Clock | None = None,
        lifetime: int = _MAX_ASSERTION_LIFETIME,
    ) -> None:
        _require_non_empty(client_id, "client_id")
        _require_non_empty(token_endpoint, "token_endpoint")
        if not isinstance(private_key_path, str | Path):
            raise ConfigurationError("private_key_path must be a file path")
        if not 1 <= lifetime <= _MAX_ASSERTION_LIFETIME:
            raise ConfigurationError("assertion lifetime must be between 1 and 60 seconds")
        if alg in FORBIDDEN_ALGORITHMS:
            raise ConfigurationError(f"algorithm {alg!r} is not permitted for client assertions")
        try:
            pem = Path(private_key_path).read_bytes()
        except OSError:
            raise ConfigurationError("private key file could not be read") from None
        key = load_private_key_pem(pem)
        if alg not in algorithms_for_key(key.public_key()):
            raise ConfigurationError("algorithm is incompatible with the private key")
        self._client_id = client_id
        self._key = key
        self._alg = alg
        self._kid = kid
        self._token_endpoint = token_endpoint
        self._clock: Clock = clock or SystemClock()
        self._lifetime = lifetime

    @property
    def client_id(self) -> str:
        """The OAuth client identifier."""
        return self._client_id

    def assertion(self) -> str:
        """Create a fresh RFC 7523 §3 client assertion."""
        now = int(self._clock.now())
        claims: dict[str, object] = {
            "iss": self._client_id,
            "sub": self._client_id,
            "aud": self._token_endpoint,
            "iat": now,
            "exp": now + self._lifetime,
            "jti": secrets.token_urlsafe(24),
        }
        return sign_compact(claims, self._key, alg=self._alg, kid=self._kid, typ=_ASSERTION_TYP)

    def apply(self, request: ExchangeRequest) -> ExchangeRequest:
        """Add ``client_id``, ``client_assertion_type`` and a fresh ``client_assertion``."""
        return request.with_form(
            {
                "client_id": self._client_id,
                "client_assertion_type": CLIENT_ASSERTION_TYPE_JWT_BEARER,
                "client_assertion": self.assertion(),
            }
        )

    def __repr__(self) -> str:
        return (
            f"PrivateKeyJwtCredential(client_id={self._client_id!r}, alg={self._alg!r}, "
            f"kid={self._kid!r})"
        )


class MtlsCredential:
    """RFC 8705 mutual-TLS client authentication.

    Authentication happens in the TLS handshake, so :meth:`apply` only adds ``client_id``. The
    transport must be built with :meth:`ssl_context` (the exchange clients do this automatically
    when they create their own ``httpx`` client).
    """

    __slots__ = ("_ca_path", "_cert_path", "_client_id", "_key_path")

    def __init__(
        self,
        cert_path: str | Path,
        key_path: str | Path,
        *,
        client_id: str,
        ca_path: str | Path | None = None,
    ) -> None:
        _require_non_empty(client_id, "client_id")
        self._cert_path = Path(cert_path)
        self._key_path = Path(key_path)
        self._ca_path = Path(ca_path) if ca_path is not None else None
        self._client_id = client_id

    @property
    def cert(self) -> tuple[str, str]:
        """``(certificate_path, key_path)``."""
        return (str(self._cert_path), str(self._key_path))

    def ssl_context(self) -> ssl.SSLContext:
        """A verifying TLS context presenting this client certificate.

        Raises:
            ConfigurationError: If the certificate or key cannot be loaded.
        """
        cafile = str(self._ca_path) if self._ca_path is not None else None
        try:
            context = ssl.create_default_context(cafile=cafile)
            context.load_cert_chain(*self.cert)
        except (OSError, ssl.SSLError):
            raise ConfigurationError("mTLS certificate or key could not be loaded") from None
        return context

    def apply(self, request: ExchangeRequest) -> ExchangeRequest:
        """Add ``client_id`` (RFC 8705 §2)."""
        return request.with_form({"client_id": self._client_id})

    def __repr__(self) -> str:
        return f"MtlsCredential(client_id={self._client_id!r}, cert={str(self._cert_path)!r})"


class SpiffeJwtSvidCredential:
    """A SPIFFE JWT-SVID presented as an RFC 7523 client assertion.

    The SVID file is re-read on every request because the SPIFFE helper rotates it in place.
    """

    __slots__ = ("_client_id", "_svid_path")

    def __init__(self, svid_path: str | Path, client_id: str) -> None:
        _require_non_empty(client_id, "client_id")
        self._svid_path = Path(svid_path)
        self._client_id = client_id

    def _read_svid(self) -> str:
        try:
            with self._svid_path.open("rb") as handle:
                raw = handle.read(_MAX_SVID_BYTES + 1)
        except OSError:
            raise DependencyError("JWT-SVID file could not be read") from None
        if len(raw) > _MAX_SVID_BYTES:
            raise DependencyError("JWT-SVID file is too large")
        try:
            svid = raw.decode("ascii").strip()
        except UnicodeDecodeError:
            raise DependencyError("JWT-SVID file is not ASCII") from None
        if svid.count(".") != 2 or any(c.isspace() for c in svid):
            raise DependencyError("JWT-SVID file does not contain a compact JWT")
        return svid

    def apply(self, request: ExchangeRequest) -> ExchangeRequest:
        """Add ``client_id``, ``client_assertion_type`` and the current JWT-SVID.

        Raises:
            DependencyError: If the SVID file is missing, unreadable or malformed.
        """
        return request.with_form(
            {
                "client_id": self._client_id,
                "client_assertion_type": CLIENT_ASSERTION_TYPE_JWT_BEARER,
                "client_assertion": self._read_svid(),
            }
        )

    def __repr__(self) -> str:
        return (
            f"SpiffeJwtSvidCredential(client_id={self._client_id!r}, path={str(self._svid_path)!r})"
        )
