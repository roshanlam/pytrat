"""Ordered agent assurance levels.

agent-profile-03 §3.5.1: ``min_assurance_level`` has no protocol-defined values; "Deployments MUST
define their own ordered set and comparison function". This module is that comparison function.
It lives in core because both resource-side policy and the TTS need it.
"""

from __future__ import annotations

from dataclasses import dataclass

from pytrat.core.errors import AuthorizationError, ConfigurationError, ReasonCode

DEFAULT_LEVELS = ("unverified", "low", "medium", "high")


@dataclass(frozen=True, slots=True)
class AssuranceOrdering:
    """A strictly ordered sequence of assurance levels, lowest first."""

    levels: tuple[str, ...] = DEFAULT_LEVELS

    def __post_init__(self) -> None:
        if not self.levels:
            raise ConfigurationError("assurance ordering must define at least one level")
        if len(set(self.levels)) != len(self.levels):
            raise ConfigurationError("assurance levels must be unique")
        if any(not level for level in self.levels):
            raise ConfigurationError("assurance levels must be non-empty strings")

    @property
    def lowest(self) -> str:
        """The least trusted level."""
        return self.levels[0]

    def is_known(self, level: str) -> bool:
        """Return True if ``level`` belongs to this ordering."""
        return level in self.levels

    def require_known(self, level: str) -> str:
        """Validate a configured level at startup.

        Raises:
            ConfigurationError: If ``level`` is not part of the ordering.
        """
        if level not in self.levels:
            raise ConfigurationError(f"unknown assurance level {level!r}")
        return level

    def minimum(self, first: str | None, second: str | None) -> str:
        """Return the lower of two levels for computing a chain minimum.

        agent-profile-03 §3.5.1: the chain value is the minimum across agents. When computing a
        minimum, an unknown or absent level is treated as the lowest level, so an unrecognised
        value can never raise the chain's assurance.
        """
        return self.levels[min(self._rank_or_lowest(first), self._rank_or_lowest(second))]

    def satisfies(self, actual: str | None, required: str) -> bool:
        """Return True if ``actual`` is at least ``required``.

        Raises:
            AuthorizationError: ``AGENT_ASSURANCE_INSUFFICIENT`` if ``actual`` is absent or not
                part of this ordering. An unknown level never satisfies a requirement.
        """
        required_rank = self.levels.index(self.require_known(required))
        if actual is None or actual not in self.levels:
            raise AuthorizationError(
                ReasonCode.AGENT_ASSURANCE_INSUFFICIENT,
                "agent chain assurance level is absent or not recognised",
            )
        return self.levels.index(actual) >= required_rank

    def _rank_or_lowest(self, level: str | None) -> int:
        return self.levels.index(level) if level in self.levels else 0
