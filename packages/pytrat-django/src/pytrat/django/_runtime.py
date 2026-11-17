"""Startup resolution of the enforcer and policy, cached on the app config (private)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from django.apps import apps
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string
from pytrat.core import ConfigurationError, ReplayStore
from pytrat.django._settings import SETTINGS_NAME, PyTraTSettings, parse_settings
from pytrat.policy import AgentDirectory, PolicySet, TransactionEnforcer, load_policy

APP_LABEL: Final = "pytrat_django"


@dataclass(frozen=True, slots=True)
class Runtime:
    """Everything the integration resolved at startup.

    Attributes:
        settings: The validated ``PYTRAT`` setting.
        enforcer: The enforcer every protected view uses.
        policies: The compiled YAML policy, if ``POLICY`` is configured.
    """

    settings: PyTraTSettings
    enforcer: TransactionEnforcer
    policies: PolicySet | None


def load_runtime() -> Runtime:
    """Read ``settings.PYTRAT``, build the enforcer and compile the YAML policy.

    Raises:
        ImproperlyConfigured: If the setting is invalid, a factory cannot be imported or returns
            the wrong type, or the policy fails to load. The process should refuse to start.
    """
    parsed = parse_settings(getattr(settings, SETTINGS_NAME, None))
    enforcer = _build(parsed.enforcer, "ENFORCER", TransactionEnforcer)
    policies: PolicySet | None = None
    if parsed.policy is not None:
        replay_store = _optional(parsed.replay_store, "REPLAY_STORE")
        directory = _optional(parsed.agent_directory, "AGENT_DIRECTORY")
        try:
            policies = load_policy(
                parsed.policy,
                replay_store=_as_replay_store(replay_store),
                agent_directory=_as_directory(directory),
            )
        except ConfigurationError as exc:
            raise ImproperlyConfigured(f"PYTRAT['POLICY'] is invalid: {exc.detail}") from exc
    return Runtime(settings=parsed, enforcer=enforcer, policies=policies)


def get_runtime() -> Runtime:
    """The runtime cached by :class:`~pytrat.django.apps.PyTraTConfig`.

    Raises:
        ImproperlyConfigured: If ``pytrat.django`` is not installed or not yet ready.
    """
    try:
        config: object = apps.get_app_config(APP_LABEL)
    except LookupError:
        raise ImproperlyConfigured("pytrat.django is not in INSTALLED_APPS") from None
    runtime = getattr(config, "runtime", None)
    if not isinstance(runtime, Runtime):
        raise ImproperlyConfigured("pytrat.django has not been initialised")
    return runtime


def get_enforcer() -> TransactionEnforcer:
    """The :class:`TransactionEnforcer` configured by ``PYTRAT['ENFORCER']``.

    Raises:
        ImproperlyConfigured: If the integration is not installed or not initialised.
    """
    return get_runtime().enforcer


def _build[T](path: str, key: str, expected: type[T]) -> T:
    instance = _call_factory(path, key)
    if not isinstance(instance, expected):
        raise ImproperlyConfigured(
            f"PYTRAT['{key}'] factory must return a {expected.__name__}, "
            f"got {type(instance).__name__}"
        )
    return instance


def _optional(path: str | None, key: str) -> object:
    return None if path is None else _call_factory(path, key)


def _call_factory(path: str, key: str) -> object:
    try:
        factory: object = import_string(path)
    except ImportError as exc:
        raise ImproperlyConfigured(f"PYTRAT['{key}'] cannot be imported: {path}") from exc
    if not callable(factory):
        raise ImproperlyConfigured(f"PYTRAT['{key}'] is not callable: {path}")
    call: Callable[[], object] = factory
    return call()


def _as_replay_store(value: object) -> ReplayStore | None:
    if value is None:
        return None
    if not callable(getattr(value, "record_once", None)):
        raise ImproperlyConfigured("PYTRAT['REPLAY_STORE'] factory must return a ReplayStore")
    store: ReplayStore = value  # type: ignore[assignment] # checked structurally above
    return store


def _as_directory(value: object) -> AgentDirectory | None:
    if value is None:
        return None
    if not callable(getattr(value, "is_registered", None)):
        raise ImproperlyConfigured(
            "PYTRAT['AGENT_DIRECTORY'] factory must return an AgentDirectory"
        )
    directory: AgentDirectory = value  # type: ignore[assignment] # checked structurally above
    return directory
