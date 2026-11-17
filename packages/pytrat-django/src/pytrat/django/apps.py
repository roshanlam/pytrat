"""Django application config: resolves and validates the configuration once, at startup."""

from __future__ import annotations

from django.apps import AppConfig
from django.core import checks
from pytrat.django._runtime import APP_LABEL, Runtime, load_runtime
from pytrat.django.checks import check_routes

__all__ = ["PyTraTConfig"]


class PyTraTConfig(AppConfig):  # type: ignore[misc] # django ships no type stubs
    """Builds the enforcer and compiles the YAML policy in :meth:`ready`.

    Invalid configuration raises ``ImproperlyConfigured`` here, so the process refuses to start
    instead of failing (or worse, passing) on the first request.

    Attributes:
        runtime: The resolved configuration, cached for the life of the app registry.
    """

    name = "pytrat.django"
    label = APP_LABEL
    verbose_name = "PyTraT Transaction Tokens"

    runtime: Runtime | None = None

    def ready(self) -> None:
        """Resolve ``settings.PYTRAT`` and register the system checks.

        Raises:
            ImproperlyConfigured: If the configuration is invalid.
        """
        checks.register(check_routes, checks.Tags.security, checks.Tags.urls)
        self.runtime = load_runtime()
