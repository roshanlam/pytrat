"""RFC 9457 problem responses for PyTraT errors.

A problem body names the stable reason code and nothing else: no claim values, no token, and the
failed check's description only when ``debug`` is set (it is value-free by contract, but it still
tells a prober which check failed).
"""

from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable, Mapping
from typing import ClassVar, Final

from starlette.requests import Request
from starlette.responses import Response
from starlette.types import Scope, Send

from pytrat.core.errors import PyTraTError, ReasonCode, RequestError, TokenError, problem_details

__all__ = [
    "PROBLEM_CONTENT_TYPE",
    "MalformedRequestError",
    "exception_handler",
    "problem_body",
    "problem_headers",
    "problem_response",
]

_log = logging.getLogger(__name__)

PROBLEM_CONTENT_TYPE: Final = "application/problem+json"

#: ASGI scope key under which the integration keeps its per-request :class:`RequestMarker`.
MARKER_KEY: Final = "pytrat"


class MalformedRequestError(RequestError):
    """The request data to be bound could not be validated (``REQUEST_MALFORMED``, HTTP 422).

    Raised before enforcement, for the same requests FastAPI itself would reject with 422. The
    response never echoes the submitted values.
    """

    http_status: ClassVar[int] = 422


class RequestMarker:
    """Per-request state shared between the middleware, the dependency and the error handler.

    Stored in the ASGI scope as a mutable object so that copies of the scope share it.

    Attributes:
        engaged: Set as soon as a ``require_transaction`` dependency starts for this request.
            From then on that dependency either denies the request or authorizes it.
        transaction_id: The ``txn`` of the authorized transaction, once there is one.
    """

    __slots__ = ("engaged", "transaction_id")

    def __init__(self) -> None:
        self.engaged = False
        self.transaction_id: str | None = None


def marker_of(scope: Scope) -> RequestMarker:
    """Return the request's marker, creating it if the middleware did not."""
    marker = scope.get(MARKER_KEY)
    if not isinstance(marker, RequestMarker):
        marker = RequestMarker()
        scope[MARKER_KEY] = marker
    return marker


def transaction_id_of(scope: Scope) -> str | None:
    """The authorized transaction id for this request, if one was established."""
    marker = scope.get(MARKER_KEY)
    return marker.transaction_id if isinstance(marker, RequestMarker) else None


def problem_body(error: PyTraTError, *, debug: bool = False) -> dict[str, object]:
    """Build the RFC 9457 problem object for ``error`` with the shared core builder.

    Only the reason code, title, status and (if verified) the transaction id are included;
    ``detail`` only when ``debug`` is set.
    """
    return problem_details(error, include_detail=debug)


def problem_headers(error: PyTraTError) -> Mapping[str, str]:
    """Headers that accompany the problem response (``WWW-Authenticate`` for 401)."""
    if error.http_status != 401:
        return {}
    # The edge rejects the user's access token; everywhere else the missing credential is the
    # Txn-Token (txn-tokens-11 §12.1). Workload credentials have no standard scheme.
    if error.reason is ReasonCode.SUBJECT_TOKEN_INVALID:
        return {"WWW-Authenticate": "Bearer"}
    if isinstance(error, TokenError):
        return {"WWW-Authenticate": "Txn-Token"}
    return {}


def _encode(body: Mapping[str, object]) -> bytes:
    return json.dumps(body, separators=(",", ":")).encode()


def problem_response(error: PyTraTError, *, debug: bool = False) -> Response:
    """A Starlette response carrying :func:`problem_body`."""
    return Response(
        _encode(problem_body(error, debug=debug)),
        status_code=error.http_status,
        headers=dict(problem_headers(error)),
        media_type=PROBLEM_CONTENT_TYPE,
    )


async def send_problem(send: Send, error: PyTraTError, *, debug: bool = False) -> None:
    """Send a complete problem response on a raw ASGI ``send`` channel."""
    content = _encode(problem_body(error, debug=debug))
    headers = [
        (b"content-type", PROBLEM_CONTENT_TYPE.encode()),
        (b"content-length", str(len(content)).encode()),
        *(
            (name.lower().encode(), value.encode())
            for name, value in problem_headers(error).items()
        ),
    ]
    await send({"type": "http.response.start", "status": error.http_status, "headers": headers})
    await send({"type": "http.response.body", "body": content})


def log_denial(error: PyTraTError, path: str) -> None:
    """Log a denial by reason code and failed check; ``detail`` is value-free by contract."""
    _log.info(
        "pytrat denied request path=%s status=%d reason=%s check=%s",
        path,
        error.http_status,
        error.reason.value,
        error.detail,
    )


def exception_handler(
    *, debug: bool = False
) -> Callable[[Request, Exception], Awaitable[Response]]:
    """Build a FastAPI exception handler for :class:`PyTraTError`.

    Args:
        debug: Include the failed check's description in the response.
    """

    async def handle(request: Request, exc: Exception) -> Response:
        if not isinstance(exc, PyTraTError):  # registered for PyTraTError only
            raise exc
        if exc.transaction_id is None:
            # A failure after authorization (inside the handler) relates to that transaction.
            exc.transaction_id = transaction_id_of(request.scope)
        log_denial(exc, request.url.path)
        return problem_response(exc, debug=debug)

    return handle
