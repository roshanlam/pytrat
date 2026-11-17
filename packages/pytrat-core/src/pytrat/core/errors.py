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
    REQUEST_MALFORMED = "REQUEST_MALFORMED"


class PyTraTError(Exception):
    """Base class for every error raised by PyTraT.

    Attributes:
        reason: Stable machine-readable reason code.
        detail: Human-readable description of the failed check. Safe to log.
        http_status: Status the framework edge should return for this error class.
        title: Short, fixed human-readable summary for this error class (RFC 9457 ``title``).
        transaction_id: The verified ``txn`` the failure relates to, when one is known. Set only
            after the token has been verified, never from unverified input.
    """

    http_status: ClassVar[int] = 500
    title: ClassVar[str] = "Transaction authorization error"

    def __init__(self, reason: ReasonCode, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail
        self.transaction_id: str | None = None

    def __repr__(self) -> str:
        return f"{type(self).__name__}(reason={self.reason.value!r}, detail={self.detail!r})"


class TokenError(PyTraTError):
    """The presented token is missing, malformed, untrusted or not currently valid."""

    http_status: ClassVar[int] = 401
    title: ClassVar[str] = "Invalid transaction token"


class AuthenticationError(PyTraTError):
    """The calling workload could not be authenticated.

    Distinct from :class:`TokenError` because a Transaction Token is never an authentication
    credential (txn-tokens-11 §13.12).
    """

    http_status: ClassVar[int] = 401
    title: ClassVar[str] = "Workload authentication required"


class AuthorizationError(PyTraTError):
    """The token is valid but does not authorize this operation."""

    http_status: ClassVar[int] = 403
    title: ClassVar[str] = "Transaction not authorized"


class RequestError(PyTraTError):
    """The request's own data (body, parameters) is malformed or ambiguous.

    Framework integrations subclass this to choose 400, 415 or 422.
    """

    http_status: ClassVar[int] = 400
    title: ClassVar[str] = "Malformed request"

    def __init__(self, detail: str) -> None:
        super().__init__(ReasonCode.REQUEST_MALFORMED, detail)


class ConfigurationError(PyTraTError):
    """Configuration is invalid. Raised at startup, never on the request path."""

    http_status: ClassVar[int] = 500
    title: ClassVar[str] = "Authorization misconfigured"

    def __init__(self, detail: str, reason: ReasonCode = ReasonCode.POLICY_INVALID) -> None:
        super().__init__(reason, detail)


class DependencyError(PyTraTError):
    """A dependency needed to make a decision is unavailable. The decision is *deny*."""

    http_status: ClassVar[int] = 503
    title: ClassVar[str] = "Authorization dependency unavailable"

    def __init__(self, detail: str, reason: ReasonCode = ReasonCode.DEPENDENCY_UNAVAILABLE) -> None:
        super().__init__(reason, detail)


PROBLEM_TYPE_PREFIX = "urn:pytrat:problem:"


def problem_details(error: PyTraTError, *, include_detail: bool = False) -> dict[str, object]:
    """Build an RFC 9457 problem document for ``error``.

    Shared by every framework integration so responses are identical. The document carries only
    the reason code, a fixed title, the status and (if verified) the transaction id. ``detail`` is
    safe by contract but still omitted unless ``include_detail`` is set, to minimise disclosure.
    """
    document: dict[str, object] = {
        "type": f"{PROBLEM_TYPE_PREFIX}{error.reason.value}",
        "title": error.title,
        "status": error.http_status,
        "reason_code": error.reason.value,
    }
    if error.transaction_id is not None:
        document["transaction_id"] = error.transaction_id
    if include_detail:
        document["detail"] = error.detail
    return document
