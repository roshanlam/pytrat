"""OAuth error responses for the token endpoint (RFC 6749 §5.2, txn-tokens-11 §11.4).

Every rejection on the request path is an :class:`OAuthError`. It carries the RFC 6749 ``error``
code returned to the client and a PyTraT :class:`~pytrat.core.errors.ReasonCode` recorded in the
audit log. Descriptions name the failed check only; they never contain tokens, keys or values.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final

from pytrat.core.errors import DependencyError, PyTraTError, ReasonCode

__all__ = ["OAuthError", "OAuthErrorCode", "translate"]


class OAuthErrorCode(StrEnum):
    """Error codes used by the token endpoint.

    txn-tokens-11 §11.4: errors are as described in RFC 6749 §5.2. ``slow_down`` and
    ``temporarily_unavailable`` are borrowed from RFC 8628 §3.5 and RFC 6749 §4.1.2.1 for rate
    limiting and dependency outages.
    """

    INVALID_REQUEST = "invalid_request"
    INVALID_CLIENT = "invalid_client"
    INVALID_GRANT = "invalid_grant"
    UNAUTHORIZED_CLIENT = "unauthorized_client"
    UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type"
    INVALID_SCOPE = "invalid_scope"
    INVALID_TARGET = "invalid_target"
    SLOW_DOWN = "slow_down"
    TEMPORARILY_UNAVAILABLE = "temporarily_unavailable"
    SERVER_ERROR = "server_error"


_DEFAULT_STATUS: Final[dict[OAuthErrorCode, int]] = {
    OAuthErrorCode.INVALID_CLIENT: 401,
    OAuthErrorCode.SLOW_DOWN: 429,
    OAuthErrorCode.TEMPORARILY_UNAVAILABLE: 503,
    OAuthErrorCode.SERVER_ERROR: 500,
}


class OAuthError(PyTraTError):
    """A token-endpoint rejection.

    Attributes:
        error: RFC 6749 §5.2 error code returned to the client.
        description: Safe, human-readable ``error_description``.
        status: HTTP status for the response.
        reason: PyTraT reason code recorded in the audit log.
    """

    def __init__(
        self,
        error: OAuthErrorCode,
        description: str,
        reason: ReasonCode,
        status: int | None = None,
    ) -> None:
        super().__init__(reason, description)
        self.error = error
        self.description = description
        self.status = status if status is not None else _DEFAULT_STATUS.get(error, 400)

    def __repr__(self) -> str:
        return (
            f"OAuthError(error={self.error.value!r}, reason={self.reason.value!r}, "
            f"description={self.description!r})"
        )


def translate(exc: PyTraTError, error: OAuthErrorCode) -> OAuthError:
    """Convert a core error raised inside one pipeline stage into an :class:`OAuthError`.

    The reason code and the (already safe) detail are preserved. A
    :class:`~pytrat.core.errors.DependencyError` always becomes ``temporarily_unavailable``: an
    unavailable dependency means *deny*, but it is not the client's fault.
    """
    if isinstance(exc, OAuthError):
        return exc
    if isinstance(exc, DependencyError):
        return OAuthError(OAuthErrorCode.TEMPORARILY_UNAVAILABLE, exc.detail, exc.reason)
    return OAuthError(error, exc.detail, exc.reason)
