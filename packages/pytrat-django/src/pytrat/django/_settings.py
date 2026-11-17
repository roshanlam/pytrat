"""Parsing and validation of the ``PYTRAT`` Django setting (private)."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from django.core.exceptions import ImproperlyConfigured

SETTINGS_NAME: Final = "PYTRAT"

_KNOWN_KEYS: Final = frozenset(
    {
        "ENFORCER",
        "POLICY",
        "PROTECTED_PREFIXES",
        "DEBUG_ERRORS",
        "REPLAY_STORE",
        "AGENT_DIRECTORY",
    }
)


@dataclass(frozen=True, slots=True)
class PyTraTSettings:
    """The validated ``PYTRAT`` setting.

    Attributes:
        enforcer: Dotted path to a zero-argument factory returning a ``TransactionEnforcer``.
        policy: Path to a YAML policy file, or None if every view declares its policy inline.
        protected_prefixes: URL path prefixes whose views must declare a transaction policy.
        debug_errors: Include the failed check's ``detail`` in error responses.
        replay_store: Dotted path to a zero-argument ``ReplayStore`` factory for YAML policies.
        agent_directory: Dotted path to a zero-argument ``AgentDirectory`` factory for YAML
            policies.
    """

    enforcer: str
    policy: str | None = None
    protected_prefixes: tuple[str, ...] = ()
    debug_errors: bool = False
    replay_store: str | None = None
    agent_directory: str | None = None


def parse_settings(raw: object) -> PyTraTSettings:
    """Validate the raw ``PYTRAT`` setting.

    Unknown keys are rejected so that a typo cannot silently drop a protection.

    Raises:
        ImproperlyConfigured: If the setting is missing or invalid.
    """
    if raw is None:
        raise _improper("the PYTRAT setting is required when pytrat.django is installed")
    if not isinstance(raw, Mapping):
        raise _improper("PYTRAT must be a dict")
    unknown = sorted(str(key) for key in raw if key not in _KNOWN_KEYS)
    if unknown:
        raise _improper(f"PYTRAT has unknown keys: {', '.join(unknown)}")
    return PyTraTSettings(
        enforcer=_dotted_path(raw, "ENFORCER", required=True) or "",
        policy=_policy_path(raw.get("POLICY")),
        protected_prefixes=_prefixes(raw.get("PROTECTED_PREFIXES", ())),
        debug_errors=_flag(raw.get("DEBUG_ERRORS", False)),
        replay_store=_dotted_path(raw, "REPLAY_STORE"),
        agent_directory=_dotted_path(raw, "AGENT_DIRECTORY"),
    )


def _dotted_path(raw: Mapping[object, object], key: str, *, required: bool = False) -> str | None:
    value = raw.get(key)
    if value is None and not required:
        return None
    if not isinstance(value, str) or "." not in value:
        raise _improper(f"PYTRAT['{key}'] must be a dotted import path")
    return value


def _policy_path(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, os.PathLike):
        value = os.fspath(value)
    if not isinstance(value, str) or not value:
        raise _improper("PYTRAT['POLICY'] must be a file path or None")
    return value


def _prefixes(value: object) -> tuple[str, ...]:
    if not isinstance(value, list | tuple):
        raise _improper("PYTRAT['PROTECTED_PREFIXES'] must be a list of path prefixes")
    prefixes: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.startswith("/"):
            raise _improper("each protected prefix must be a string starting with '/'")
        prefixes.append(item)
    return tuple(prefixes)


def _flag(value: object) -> bool:
    if not isinstance(value, bool):
        raise _improper("PYTRAT['DEBUG_ERRORS'] must be a bool")
    return value


def _improper(message: str) -> ImproperlyConfigured:
    error: ImproperlyConfigured = ImproperlyConfigured(message)
    return error
