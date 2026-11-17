"""``TransactionMiddleware``: fail closed for forgotten decorators under protected prefixes."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping, Sequence

from asgiref.sync import iscoroutinefunction, markcoroutinefunction

from django.http import HttpRequest, HttpResponse
from pytrat.core import AuthorizationError, ReasonCode
from pytrat.django._http import problem_response
from pytrat.django._runtime import get_runtime
from pytrat.django.decorators import guard_of, is_exempt

__all__ = ["TransactionMiddleware", "is_protected_path"]

type GetResponse = Callable[[HttpRequest], HttpResponse | Awaitable[HttpResponse]]


class TransactionMiddleware:
    """Denies requests under ``PYTRAT['PROTECTED_PREFIXES']`` whose view declares no policy.

    A view counts as covered if it is decorated with ``@require_transaction`` or ``@exempt``.
    Anything else under a protected prefix gets 403 ``POLICY_NOT_FOUND`` before the view runs.
    The decorator performs enforcement; this middleware only makes a forgotten decorator fail
    closed. Works under WSGI and ASGI.
    """

    sync_capable = True
    async_capable = True

    def __init__(self, get_response: GetResponse) -> None:
        self.get_response = get_response
        self._is_async = iscoroutinefunction(get_response)
        if self._is_async:
            markcoroutinefunction(self)

    def __call__(self, request: HttpRequest) -> HttpResponse | Awaitable[HttpResponse]:
        """Pass the request on; the check happens in :meth:`process_view`."""
        return self.get_response(request)

    def process_view(
        self,
        request: HttpRequest,
        view_func: object,
        view_args: Sequence[object],
        view_kwargs: Mapping[str, object],
    ) -> HttpResponse | None:
        """Return a 403 problem response for an uncovered view under a protected prefix."""
        settings = get_runtime().settings
        if not is_protected_path(str(request.path_info), settings.protected_prefixes):
            return None
        if guard_of(view_func) is not None or is_exempt(view_func):
            return None
        error = AuthorizationError(
            ReasonCode.POLICY_NOT_FOUND, "view under a protected prefix declares no policy"
        )
        return problem_response(error, debug=settings.debug_errors)


def is_protected_path(path: str, prefixes: Sequence[str]) -> bool:
    """Whether ``path`` starts with any protected prefix."""
    return any(path.startswith(prefix) for prefix in prefixes)
