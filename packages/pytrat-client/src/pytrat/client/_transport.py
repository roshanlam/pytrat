"""URL policy and bounded body reading shared by every I/O shell (private)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

import httpx

from pytrat.core.errors import ConfigurationError

_LOCALHOSTS: Final = frozenset({"localhost", "127.0.0.1", "::1"})
_DEFAULT_PORTS: Final = {"http": 80, "https": 443}


@dataclass(frozen=True, slots=True)
class Origin:
    """A normalised ``scheme://host:port`` origin: lowercase scheme and host, explicit port."""

    scheme: str
    host: str
    port: int

    def __str__(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}:{self.port}"


def origin_of(url: httpx.URL) -> Origin | None:
    """Return the normalised origin of an absolute http(s) URL, or None if it has none."""
    scheme = url.scheme.lower()
    if scheme not in _DEFAULT_PORTS or not url.host:
        return None
    port = url.port if url.port is not None else _DEFAULT_PORTS[scheme]
    return Origin(scheme=scheme, host=url.host.lower().rstrip("."), port=port)


def _parse(raw: str, what: str) -> httpx.URL:
    if not raw:
        raise ConfigurationError(f"{what} must be a non-empty URL string")
    try:
        return httpx.URL(raw)
    except httpx.InvalidURL:
        raise ConfigurationError(f"{what} is not a valid URL") from None


def _check_transport_security(origin: Origin, *, allow_insecure_localhost: bool, what: str) -> None:
    if origin.scheme == "https":
        return
    # PyTraT profile: plaintext HTTP only for local development, and only when explicitly enabled.
    if allow_insecure_localhost and origin.host in _LOCALHOSTS:
        return
    raise ConfigurationError(f"{what} must use https")


def require_secure_endpoint(raw: str, *, allow_insecure_localhost: bool, what: str) -> httpx.URL:
    """Validate a configured endpoint URL (token endpoint, JWKS URL).

    Raises:
        ConfigurationError: If the URL is malformed, not absolute, carries credentials or a
            fragment, or is not HTTPS (outside the explicit localhost exception).
    """
    url = _parse(raw, what)
    origin = origin_of(url)
    if origin is None:
        raise ConfigurationError(f"{what} must be an absolute http(s) URL")
    if url.userinfo or url.fragment:
        raise ConfigurationError(f"{what} must not contain credentials or a fragment")
    _check_transport_security(origin, allow_insecure_localhost=allow_insecure_localhost, what=what)
    return url


def parse_trusted_origin(raw: str, *, allow_insecure_localhost: bool) -> Origin:
    """Parse one ``trusted_destinations`` entry into a normalised origin.

    Raises:
        ConfigurationError: If the entry is not exactly ``scheme://host[:port]``.
    """
    what = "trusted destination"
    url = _parse(raw, what)
    origin = origin_of(url)
    if origin is None:
        raise ConfigurationError(f"{what} must be an absolute http(s) origin")
    if url.userinfo or url.query or url.fragment or url.raw_path not in (b"", b"/"):
        raise ConfigurationError(f"{what} must be exactly scheme://host[:port]")
    _check_transport_security(origin, allow_insecure_localhost=allow_insecure_localhost, what=what)
    return origin


class BoundedBody:
    """Accumulates a response body and fails as soon as it exceeds ``limit`` bytes.

    Sync and async shells feed it chunk by chunk, so an oversized body is never fully buffered.
    """

    __slots__ = ("_chunks", "_limit", "_size")

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._size = 0
        self._chunks: list[bytes] = []

    def feed(self, chunk: bytes) -> bool:
        """Add a chunk. Returns False (and stops accumulating) once the limit is exceeded."""
        self._size += len(chunk)
        if self._size > self._limit:
            self._chunks.clear()
            return False
        self._chunks.append(chunk)
        return True

    @property
    def exceeded(self) -> bool:
        """True if more than ``limit`` bytes were fed."""
        return self._size > self._limit

    def value(self) -> bytes:
        """The accumulated body."""
        return b"".join(self._chunks)


__all__ = [
    "BoundedBody",
    "Origin",
    "origin_of",
    "parse_trusted_origin",
    "require_secure_endpoint",
]
