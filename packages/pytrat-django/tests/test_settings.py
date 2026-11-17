from __future__ import annotations

from pathlib import Path

import pytest
from django.apps import apps
from django.core.exceptions import ImproperlyConfigured
from django.test.utils import override_settings

import pytrat_django_support as support
from pytrat.django import PyTraTSettings, get_enforcer, get_runtime, parse_settings
from pytrat.policy import TransactionEnforcer


def test_parse_minimal_settings() -> None:
    assert parse_settings({"ENFORCER": "a.b"}) == PyTraTSettings(enforcer="a.b")


def test_parse_full_settings() -> None:
    parsed = parse_settings(
        {
            "ENFORCER": "a.b",
            "POLICY": Path("policy.yaml"),
            "PROTECTED_PREFIXES": ("/internal/",),
            "DEBUG_ERRORS": True,
            "REPLAY_STORE": "a.store",
            "AGENT_DIRECTORY": "a.directory",
        }
    )
    assert parsed.policy == "policy.yaml"
    assert parsed.protected_prefixes == ("/internal/",)
    assert parsed.debug_errors
    assert (parsed.replay_store, parsed.agent_directory) == ("a.store", "a.directory")


@pytest.mark.parametrize(
    ("raw", "match"),
    [
        (None, "required"),
        (["ENFORCER"], "must be a dict"),
        ({}, "ENFORCER"),
        ({"ENFORCER": "nodots"}, "ENFORCER"),
        ({"ENFORCER": 3}, "ENFORCER"),
        ({"ENFORCER": "a.b", "PROTECTED_PREFIX": ["/x/"]}, "unknown keys: PROTECTED_PREFIX"),
        ({"ENFORCER": "a.b", "POLICY": ""}, "POLICY"),
        ({"ENFORCER": "a.b", "POLICY": 1}, "POLICY"),
        ({"ENFORCER": "a.b", "PROTECTED_PREFIXES": "/internal/"}, "PROTECTED_PREFIXES"),
        ({"ENFORCER": "a.b", "PROTECTED_PREFIXES": ["internal/"]}, "start"),
        ({"ENFORCER": "a.b", "PROTECTED_PREFIXES": [1]}, "start"),
        ({"ENFORCER": "a.b", "DEBUG_ERRORS": "yes"}, "DEBUG_ERRORS"),
        ({"ENFORCER": "a.b", "REPLAY_STORE": "x"}, "REPLAY_STORE"),
    ],
)
def test_bad_settings_are_improperly_configured(raw, match) -> None:
    with pytest.raises(ImproperlyConfigured, match=match):
        parse_settings(raw)


def ready_with(**overrides: object) -> None:
    with override_settings(PYTRAT=support.pytrat_settings(**overrides)):
        support.reload_runtime()


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"ENFORCER": "pytrat_django_support.missing"}, "cannot be imported"),
        ({"ENFORCER": "no_such_module_xyz.factory"}, "cannot be imported"),
        ({"ENFORCER": "pytrat_django_support.NOT_CALLABLE"}, "not callable"),
        ({"ENFORCER": "pytrat_django_support.not_an_enforcer"}, "TransactionEnforcer"),
        ({"POLICY": "/nonexistent/policy.yaml"}, "POLICY"),
        ({"REPLAY_STORE": "pytrat_django_support.build_nothing"}, "ReplayStore"),
        ({"AGENT_DIRECTORY": "pytrat_django_support.build_nothing"}, "AgentDirectory"),
        ({"DEBUG_ERRORS": 1}, "DEBUG_ERRORS"),
    ],
)
def test_app_ready_fails_at_startup_on_bad_config(overrides, match) -> None:
    with pytest.raises(ImproperlyConfigured, match=match):
        ready_with(**overrides)


def test_app_ready_fails_without_pytrat_setting() -> None:
    from django.conf import settings

    with override_settings():
        del settings.PYTRAT
        with pytest.raises(ImproperlyConfigured, match="required"):
            support.reload_runtime()


def test_app_ready_accepts_replay_store_and_agent_directory() -> None:
    with override_settings(
        PYTRAT=support.pytrat_settings(
            REPLAY_STORE="pytrat_django_support.build_replay_store",
            AGENT_DIRECTORY="pytrat_django_support.build_agent_directory",
        )
    ):
        support.reload_runtime()
        assert get_runtime().policies is not None


def test_enforcer_is_resolved_once_and_cached() -> None:
    first = get_enforcer()
    assert isinstance(first, TransactionEnforcer)
    assert get_enforcer() is first


def test_get_runtime_when_app_not_installed(monkeypatch) -> None:
    def missing(label: str):
        raise LookupError(label)

    monkeypatch.setattr(apps, "get_app_config", missing)
    with pytest.raises(ImproperlyConfigured, match="INSTALLED_APPS"):
        get_runtime()


def test_get_runtime_before_ready() -> None:
    config = apps.get_app_config("pytrat_django")
    saved, config.runtime = config.runtime, None
    try:
        with pytest.raises(ImproperlyConfigured, match="initialised"):
            get_enforcer()
    finally:
        config.runtime = saved
