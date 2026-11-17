"""Validated, immutable configuration for the FastAPI integration."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from pytrat.core.errors import ConfigurationError

__all__ = ["PyTraTSettings", "normalise_prefixes"]


def normalise_prefixes(prefixes: Iterable[str]) -> tuple[str, ...]:
    """Validate path prefixes and strip trailing slashes (``"/"`` stays the root).

    Raises:
        ConfigurationError: If ``prefixes`` is a single string or a prefix does not start with
            ``/``.
    """
    if isinstance(prefixes, str):
        raise ConfigurationError("protected_prefixes must be a collection of paths, not a string")
    normalised: list[str] = []
    for prefix in prefixes:
        if not prefix.startswith("/"):
            raise ConfigurationError("protected prefixes must start with '/'")
        normalised.append(prefix.rstrip("/") or "/")
    return tuple(dict.fromkeys(normalised))


@dataclass(frozen=True, slots=True)
class PyTraTSettings:
    """Configuration of one :class:`~pytrat.fastapi.PyTraT` instance.

    Attributes:
        service: This service's name, recorded in audit events.
        protected_prefixes: Every request whose path equals or lies under one of these must pass
            through a ``require_transaction`` dependency or an explicitly exempt handler.
        debug: Include the failed check's (always value-free) description in error responses.

    Raises:
        ConfigurationError: On construction, if a value is invalid.
    """

    service: str
    protected_prefixes: tuple[str, ...] = ()
    debug: bool = False

    def __post_init__(self) -> None:
        if not self.service:
            raise ConfigurationError("service must be a non-empty name")
        object.__setattr__(self, "protected_prefixes", normalise_prefixes(self.protected_prefixes))

    def is_protected(self, path: str) -> bool:
        """True if ``path`` equals or lies under a protected prefix."""
        return any(_under(path, prefix) for prefix in self.protected_prefixes)


def _under(path: str, prefix: str) -> bool:
    return prefix in {"/", path} or path.startswith(prefix + "/")
