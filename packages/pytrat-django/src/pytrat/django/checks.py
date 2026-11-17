"""Django system checks: every view under a protected prefix declares a policy."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from typing import Final

from django.conf import settings
from django.core import checks
from django.core.exceptions import ImproperlyConfigured
from django.urls import URLPattern, URLResolver, get_resolver
from pytrat.django._runtime import Runtime, get_runtime
from pytrat.django.decorators import guard_of, is_exempt
from pytrat.django.middleware import is_protected_path

__all__ = ["check_routes"]

MIDDLEWARE_PATH: Final = "pytrat.django.middleware.TransactionMiddleware"


def check_routes(app_configs: object = None, **kwargs: object) -> list[checks.CheckMessage]:
    """Report misconfigured transaction protection.

    * ``pytrat.E001``: a view under a protected prefix has neither ``@require_transaction`` nor
      ``@exempt`` (the middleware would deny it at runtime; this surfaces it at startup).
    * ``pytrat.E002``: a view's ``policy_id`` is not in the YAML policy.
    * ``pytrat.W001``: protected prefixes are configured but ``TransactionMiddleware`` is not.
    """
    try:
        runtime = get_runtime()
    except ImproperlyConfigured as exc:
        return [checks.Error(str(exc), id="pytrat.E000")]
    messages: list[checks.CheckMessage] = []
    prefixes = runtime.settings.protected_prefixes
    if prefixes and MIDDLEWARE_PATH not in _middleware():
        messages.append(
            checks.Warning(
                "PYTRAT['PROTECTED_PREFIXES'] is set but TransactionMiddleware is not installed",
                hint=f"add {MIDDLEWARE_PATH!r} to MIDDLEWARE",
                id="pytrat.W001",
            )
        )
    for route, view in _walk(get_resolver().url_patterns, "/"):
        messages.extend(_check_view(route, view, prefixes, runtime))
    return messages


def _check_view(
    route: str, view: object, prefixes: Sequence[str], runtime: Runtime
) -> Iterator[checks.CheckMessage]:
    guard = guard_of(view)
    if guard is None:
        if is_protected_path(route, prefixes) and not is_exempt(view):
            yield checks.Error(
                f"view for {route!r} is under a protected prefix but has no transaction policy",
                hint="decorate it with @require_transaction(...) or @exempt",
                obj=view,
                id="pytrat.E001",
            )
        return
    try:
        guard.resolve(runtime)
    except ImproperlyConfigured as exc:
        yield checks.Error(str(exc), obj=view, id="pytrat.E002")


def _walk(patterns: Sequence[object], prefix: str) -> Iterator[tuple[str, object]]:
    for entry in patterns:
        route = prefix + _route_text(entry)
        if isinstance(entry, URLResolver):
            yield from _walk(entry.url_patterns, route)
        elif isinstance(entry, URLPattern):
            yield route, entry.callback


def _route_text(entry: object) -> str:
    # Best effort for regex routes: drop anchors so the literal prefix can be compared.
    text = str(getattr(entry, "pattern", ""))
    return text.removeprefix("^").removesuffix("$")


def _middleware() -> Sequence[str]:
    configured: object = getattr(settings, "MIDDLEWARE", None) or ()
    return (
        [item for item in configured if isinstance(item, str)]
        if isinstance(configured, list | tuple)
        else []
    )
