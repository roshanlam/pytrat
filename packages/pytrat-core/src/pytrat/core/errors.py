"""Structured exceptions.

Every error PyTraT raises derives from :class:`PyTraTError` and carries a stable
:class:`ReasonCode`. Reason codes are public API: new codes may be added, existing codes are never
renamed or removed.

Error ``detail`` strings name the check that failed. They never contain tokens, key material or the
values being compared, so they are always safe to log and to return to callers.
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar


class ReasonCode(StrEnum):
    """Stable, machine-readable reason for a rejection."""

    TOKEN_MISSING = "TOKEN_MISSING"
    TOKEN_MALFORMED = "TOKEN_MALFORMED"
    TOKEN_TYPE_INVALID = "TOKEN_TYPE_INVALID"
    ALGORITHM_NOT_ALLOWED = "ALGORITHM_NOT_ALLOWED"
    KEY_UNKNOWN = "KEY_UNKNOWN"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    CLAIM_MISSING = "CLAIM_MISSING"
    CLAIM_INVALID = "CLAIM_INVALID"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"
    TOKEN_NOT_YET_VALID = "TOKEN_NOT_YET_VALID"
    LIFETIME_EXCEEDED = "LIFETIME_EXCEEDED"
    TRUST_DOMAIN_MISMATCH = "TRUST_DOMAIN_MISMATCH"
    ISSUER_MISMATCH = "ISSUER_MISMATCH"
    SCOPE_INSUFFICIENT = "SCOPE_INSUFFICIENT"
    TRANSACTION_CONTEXT_MISSING = "TRANSACTION_CONTEXT_MISSING"
    TRANSACTION_CONTEXT_MISMATCH = "TRANSACTION_CONTEXT_MISMATCH"
    CALLER_NOT_ALLOWED = "CALLER_NOT_ALLOWED"
    WORKLOAD_UNAUTHENTICATED = "WORKLOAD_UNAUTHENTICATED"
    REPLAY_DETECTED = "REPLAY_DETECTED"
    POLICY_NOT_FOUND = "POLICY_NOT_FOUND"
    POLICY_INVALID = "POLICY_INVALID"
    DEPENDENCY_UNAVAILABLE = "DEPENDENCY_UNAVAILABLE"
    AGENT_UNVERIFIED = "AGENT_UNVERIFIED"
    AGENT_HOP_LIMIT_EXCEEDED = "AGENT_HOP_LIMIT_EXCEEDED"
    AGENT_ASSURANCE_INSUFFICIENT = "AGENT_ASSURANCE_INSUFFICIENT"
    AGENT_NOT_ALLOWED = "AGENT_NOT_ALLOWED"
    AGENT_CONTEXT_MISSING = "AGENT_CONTEXT_MISSING"
    REPLACEMENT_WIDENS_AUTHORIZATION = "REPLACEMENT_WIDENS_AUTHORIZATION"
    REPLACEMENT_LIMIT_EXCEEDED = "REPLACEMENT_LIMIT_EXCEEDED"
    DESTINATION_NOT_TRUSTED = "DESTINATION_NOT_TRUSTED"
    EXCHANGE_FAILED = "EXCHANGE_FAILED"
    SUBJECT_TOKEN_INVALID = "SUBJECT_TOKEN_INVALID"
    ISSUANCE_NOT_AUTHORIZED = "ISSUANCE_NOT_AUTHORIZED"
    RATE_LIMITED = "RATE_LIMITED"
    TOOL_ARGUMENTS_INVALID = "TOOL_ARGUMENTS_INVALID"
    TOOL_RESULT_BLOCKED = "TOOL_RESULT_BLOCKED"


class PyTraTError(Exception):
    """Base class for every error raised by PyTraT.

    Attributes:
        reason: Stable machine-readable reason code.
        detail: Human-readable description of the failed check. Safe to log.
        http_status: Status the framework edge should return for this error class.
    """

    http_status: ClassVar[int] = 500

    def __init__(self, reason: ReasonCode, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail

    def __repr__(self) -> str:
        return f"{type(self).__name__}(reason={self.reason.value!r}, detail={self.detail!r})"


class TokenError(PyTraTError):
    """The presented token is missing, malformed, untrusted or not currently valid."""

    http_status: ClassVar[int] = 401


class AuthenticationError(PyTraTError):
    """The calling workload could not be authenticated.

    Distinct from :class:`TokenError` because a Transaction Token is never an authentication
    credential (txn-tokens-11 §13.12).
    """

    http_status: ClassVar[int] = 401


class AuthorizationError(PyTraTError):
    """The token is valid but does not authorize this operation."""

    http_status: ClassVar[int] = 403


class ConfigurationError(PyTraTError):
    """Configuration is invalid. Raised at startup, never on the request path."""

    http_status: ClassVar[int] = 500

    def __init__(self, detail: str, reason: ReasonCode = ReasonCode.POLICY_INVALID) -> None:
        super().__init__(reason, detail)


class DependencyError(PyTraTError):
    """A dependency needed to make a decision is unavailable. The decision is *deny*."""

    http_status: ClassVar[int] = 503

    def __init__(self, detail: str, reason: ReasonCode = ReasonCode.DEPENDENCY_UNAVAILABLE) -> None:
        super().__init__(reason, detail)
