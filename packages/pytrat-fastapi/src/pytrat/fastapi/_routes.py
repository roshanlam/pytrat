"""Startup-time view of an application's routes (private).

FastAPI 0.16x keeps included routers lazily and exposes their effective routes (with prefixes and
router-level dependencies) through ``fastapi.routing.iter_route_contexts``; older versions copy
included routes into ``app.routes``. :func:`iter_routes` hides that difference.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Literal

from starlette.convertors import PathConvertor
from starlette.routing import BaseRoute, Mount, Route, WebSocketRoute
from starlette.types import Scope

from fastapi.routing import APIRoute, APIWebSocketRoute

if TYPE_CHECKING:
    from fastapi.dependencies.models import Dependant

__all__ = ["RouteView", "could_match_prefix", "iter_routes", "route_path"]

type RouteKind = Literal["http", "websocket", "mount", "other"]

_CONVERTER: Final = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)(?::[A-Za-z_]+)?\}")


@dataclass(frozen=True, slots=True)
class RouteView:
    """One effective route.

    Attributes:
        route: The object the router stores in ``scope["route"]`` when it selects this route.
        path: The full path template, with ``{name}`` parameters.
        path_regex: The compiled pattern the router matches requests against.
        methods: HTTP methods (empty for non-HTTP routes).
        kind: What sort of route this is.
        endpoint: The handler, if the route has one.
        dependant: FastAPI's dependency tree, for API routes.
        embed_body_fields: Whether FastAPI embeds body parameters under their names.
        catch_all: True if a parameter can span several path segments.
    """

    route: BaseRoute
    path: str
    path_regex: re.Pattern[str]
    methods: frozenset[str]
    kind: RouteKind
    endpoint: object | None
    dependant: Dependant | None
    embed_body_fields: bool
    catch_all: bool

    @property
    def label(self) -> str:
        """``"METHOD[,METHOD] /path"`` for messages."""
        methods = ",".join(sorted(self.methods)) or self.kind.upper()
        return f"{methods} {self.path}"


def _kind(route: BaseRoute) -> RouteKind:
    if isinstance(route, APIRoute | Route):
        return "http"
    if isinstance(route, APIWebSocketRoute | WebSocketRoute):
        return "websocket"
    if isinstance(route, Mount):
        return "mount"
    return "other"


def _view(original: BaseRoute, effective: object) -> RouteView:
    convertors = getattr(effective, "param_convertors", None) or {}
    path_format = getattr(effective, "path_format", None) or getattr(effective, "path", "") or ""
    pattern = getattr(effective, "path_regex", None)
    dependant = (
        getattr(effective, "dependant", None)
        if isinstance(original, APIRoute | APIWebSocketRoute)
        else None
    )
    return RouteView(
        route=original,
        path=_CONVERTER.sub(r"{\1}", path_format),
        path_regex=pattern if isinstance(pattern, re.Pattern) else re.compile(r"(?!)"),
        methods=frozenset(getattr(effective, "methods", None) or ()),
        kind=_kind(original),
        endpoint=getattr(effective, "endpoint", None),
        dependant=dependant,
        embed_body_fields=bool(getattr(effective, "_embed_body_fields", False)),
        catch_all=any(isinstance(c, PathConvertor) for c in convertors.values()),
    )


def iter_routes(routes: Sequence[BaseRoute]) -> Iterator[RouteView]:
    """Yield every effective route of an application, including routes of included routers."""
    try:
        from fastapi.routing import iter_route_contexts  # noqa: PLC0415 - FastAPI >= 0.16x
    except ImportError:  # pragma: no cover - older FastAPI copies included routes into app.routes
        for route in routes:
            yield _view(route, route)
        return
    for context in iter_route_contexts(routes):
        yield _view(context.original_route, context)


def _segments(path: str) -> list[str]:
    return [] if path == "/" else path.strip("/").split("/")


def could_match_prefix(view: RouteView, prefix: str) -> bool:
    """True if some request under ``prefix`` could be routed to ``view``.

    Parameters match any single segment; a catch-all parameter or a mount matches everything
    below it. Errs on the side of "could match", which only ever makes the startup check stricter.
    """
    route_segments = _segments(view.path)
    for index, expected in enumerate(_segments(prefix)):
        if index >= len(route_segments):
            # A mount (or catch-all) shorter than the prefix still serves paths below it.
            return view.kind == "mount"
        actual = route_segments[index]
        if "{" in actual:
            if view.catch_all:
                return True
            continue
        if actual != expected:
            return False
    return True


def route_path(scope: Scope) -> str:
    """The request path relative to the application's ``root_path``, as the router sees it."""
    path: str = scope.get("path", "")
    root_path: str = scope.get("root_path", "")
    if root_path and path.startswith(root_path + "/"):
        return path[len(root_path) :]
    return path
