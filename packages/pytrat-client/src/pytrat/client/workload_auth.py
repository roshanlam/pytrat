"""Outbound workload authentication to resource services.

Pairs with :class:`pytrat.core.workload.WorkloadJwtAuthenticator`: every request carries a fresh,
short-lived workload JWT in the ``Workload-Identity`` header, addressed to the destination
service. This is how the caller proves *who it is*; the Txn-Token only says *what was authorized*
(txn-tokens-11 §13.12).
"""

from __future__ import annotations

import secrets
from collections.abc import Generator, Mapping
from pathlib import Path
from typing import Final

import httpx

from pytrat.client._transport import Origin, origin_of, parse_trusted_origin
from pytrat.core.clock import Clock, SystemClock
from pytrat.core.crypto import algorithms_for_key, load_private_key_pem, sign_compact
from pytrat.core.errors import AuthorizationError, ConfigurationError, ReasonCode
from pytrat.core.workload import DEFAULT_WORKLOAD_JWT_HEADER

__all__ = ["WorkloadJwtAuth"]

_TYP: Final = "wit+jwt"
_MAX_LIFETIME: Final = 300


class WorkloadJwtAuth(httpx.Auth):
    """``httpx.Auth`` that signs a per-request workload JWT for the destination's audience.

    Args:
        workload_id: This workload's identifier (the JWT ``sub``).
        private_key_path: PEM private key file (never an inline string).
        kid: Key id published in the receiving services' trusted workload key set.
        alg: Signing algorithm compatible with the key.
        audiences: Destination origin (``scheme://host[:port]``) → audience the destination
            expects. A request to any other origin is refused.
        lifetime: JWT lifetime in seconds (default 60, at most 300).
    """

    def __init__(
        self,
        *,
        workload_id: str,
        private_key_path: str | Path,
        kid: str,
        alg: str,
        audiences: Mapping[str, str],
        lifetime: int = 60,
        header: str = DEFAULT_WORKLOAD_JWT_HEADER,
        clock: Clock | None = None,
        allow_insecure_localhost: bool = False,
    ) -> None:
        if not workload_id or not kid:
            raise ConfigurationError("workload_id and kid must be set")
        if not 0 < lifetime <= _MAX_LIFETIME:
            raise ConfigurationError("workload JWT lifetime must be between 1 and 300 seconds")
        self._key = load_private_key_pem(Path(private_key_path).read_bytes())
        if alg not in algorithms_for_key(self._key.public_key()):
            raise ConfigurationError("algorithm is incompatible with the workload key")
        self._audiences: dict[Origin, str] = {
            parse_trusted_origin(origin, allow_insecure_localhost=allow_insecure_localhost): aud
            for origin, aud in audiences.items()
        }
        if not self._audiences:
            raise ConfigurationError("at least one destination audience is required")
        self._workload_id = workload_id
        self._kid = kid
        self._alg = alg
        self._lifetime = lifetime
        self._header = header
        self._clock: Clock = clock or SystemClock()

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        """Attach a fresh workload JWT addressed to the request's destination."""
        origin = origin_of(request.url)
        audience = self._audiences.get(origin) if origin else None
        if audience is None:
            raise AuthorizationError(
                ReasonCode.DESTINATION_NOT_TRUSTED, "no workload audience for this destination"
            )
        now = int(self._clock.now())
        claims = {
            "sub": self._workload_id,
            "aud": audience,
            "iat": now,
            "exp": now + self._lifetime,
            "jti": secrets.token_urlsafe(16),
        }
        request.headers[self._header] = sign_compact(
            claims, self._key, alg=self._alg, kid=self._kid, typ=_TYP
        )
        yield request

    def __repr__(self) -> str:
        return f"WorkloadJwtAuth(workload_id={self._workload_id!r}, kid={self._kid!r})"
