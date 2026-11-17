"""Configuration errors that carry the policy key they refer to (private)."""

from __future__ import annotations

from pytrat.core.errors import ConfigurationError, ReasonCode


class PolicyFieldError(ConfigurationError):
    """A compile-time check failed for one policy key.

    The loader uses ``field`` (and ``index`` for route-level checks) to build the dotted location
    in its message. ``message`` never contains configured values that could be secrets.
    """

    def __init__(
        self,
        field: str,
        message: str,
        reason: ReasonCode = ReasonCode.POLICY_INVALID,
        *,
        index: int | None = None,
    ) -> None:
        super().__init__(f"{field}: {message}", reason)
        self.field = field
        self.message = message
        self.index = index
