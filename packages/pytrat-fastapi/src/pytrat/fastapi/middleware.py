"""Fail-closed guard for protected path prefixes.

:class:`TransactionMiddleware` is a pure ASGI middleware. For every request under a protected
prefix it watches the response: unless a ``require_transaction`` dependency took charge of the
request, or the handler is explicitly exempt, the response is replaced with 403
``POLICY_NOT_FOUND``. A forgotten dependency therefore never yields a successful response.

This is the runtime backstop. The handler of an unguarded route has already run when its response
starts, so the primary defence is the startup check
(:meth:`~pytrat.fastapi.PyTraT.assert_all_routes_covered`), which refuses to start an application
that has such a route.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from pytrat.core.errors import AuthorizationError, ReasonCode
from pytrat.fastapi._routes import route_path
from pytrat.fastapi.responses import MARKER_KEY, RequestMarker, log_denial, send_problem
from pytrat.fastapi.settings import PyTraTSettings

__all__ = ["TransactionMiddleware"]

_log = logging.getLogger(__name__)

# RFC 6455 §7.4.1: policy violation. Closing before accept makes the server answer HTTP 403.
_WS_POLICY_VIOLATION = 1008


def _endpoint(scope: Scope) -> object | None:
    endpoint = scope.get("endpoint")
    if endpoint is None:
        endpoint = getattr(scope.get("route"), "endpoint", None)
    return endpoint


class TransactionMiddleware:
    """Deny any response under a protected prefix that no transaction requirement guarded.

    Args:
        app: The wrapped ASGI application.
        settings: Supplies the protected prefixes and the ``debug`` flag.
        is_exempt: Returns True for handlers explicitly exempted with ``PyTraT.exempt``. Called
            per request, so exemptions registered after installation are honoured.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        settings: PyTraTSettings,
        is_exempt: Callable[[object], bool],
    ) -> None:
        self._app = app
        self._settings = settings
        self._is_exempt = is_exempt

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Run the application, replacing an unguarded response under a protected prefix."""
        if scope["type"] not in {"http", "websocket"} or not self._settings.is_protected(
            route_path(scope)
        ):
            await self._app(scope, receive, send)
            return
        marker = RequestMarker()
        scope[MARKER_KEY] = marker
        blocked = False

        async def guarded_send(message: Message) -> None:
            nonlocal blocked
            if blocked:
                return
            starting = message["type"] in {"http.response.start", "websocket.accept"}
            if starting and not self._allowed(scope, marker):
                blocked = True
                await self._deny(scope, send)
                return
            await send(message)

        await self._app(scope, receive, guarded_send)

    def _allowed(self, scope: Scope, marker: RequestMarker) -> bool:
        # A websocket can never be guarded by the dependency (it needs an HTTP request).
        engaged = marker.engaged and scope["type"] == "http"
        return engaged or self._is_exempt(_endpoint(scope))

    async def _deny(self, scope: Scope, send: Send) -> None:
        error = AuthorizationError(
            ReasonCode.POLICY_NOT_FOUND,
            "route under a protected prefix has no transaction requirement",
        )
        log_denial(error, route_path(scope))
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": _WS_POLICY_VIOLATION})
            return
        await send_problem(send, error, debug=self._settings.debug)
