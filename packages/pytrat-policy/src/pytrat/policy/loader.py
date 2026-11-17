"""Load a YAML (or already-parsed) policy document into a compiled :class:`PolicySet`.

YAML is parsed with the safe loader only. Duplicate mapping keys are rejected, because a
silently overridden key can drop a constraint. Error messages name the source and the dotted
location of the bad key, never the configured values.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Final

import yaml
from pydantic import ValidationError
from pydantic_core import ErrorDetails

from pytrat.core.errors import ConfigurationError
from pytrat.core.replay import ReplayStore
from pytrat.policy.compiler import check_version, compile_policy
from pytrat.policy.evaluator import AgentDirectory, PolicySet
from pytrat.policy.model import PolicyDocument

__all__ = ["PolicySource", "load_policy", "load_policy_text"]

type PolicySource = str | os.PathLike[str] | Mapping[str, object]

_MAX_REPORTED_ERRORS: Final = 10
_MESSAGES: Final = {
    "extra_forbidden": "unknown key",
    "missing": "required key is missing",
}


def load_policy(
    source: PolicySource,
    *,
    expected_trust_domain: str | None = None,
    replay_store: ReplayStore | None = None,
    agent_directory: AgentDirectory | None = None,
) -> PolicySet:
    """Load and compile a policy.

    Args:
        source: A path to a YAML file (``str`` or path-like), or an already-parsed mapping.
        expected_trust_domain: If set, the document's ``trust_domain`` must equal it (normally
            the verifier's ``VerifierSettings.trust_domain``).
        replay_store: Store used by ``single_use`` resources.
        agent_directory: Directory used by ``require_verified_agent`` resources.

    Raises:
        ConfigurationError: If the file cannot be read, is not valid YAML, or fails schema or
            compile-time validation. The message is ``"<source>: <location>: <problem>"``.
    """
    if isinstance(source, Mapping):
        label = "<mapping>"
        raw: object = source
    else:
        path = Path(source)
        label = str(path)
        raw = _parse_yaml(_read(path, label), label)
    return _compile(raw, label, expected_trust_domain, replay_store, agent_directory)


def load_policy_text(
    text: str,
    *,
    source: str = "<string>",
    expected_trust_domain: str | None = None,
    replay_store: ReplayStore | None = None,
    agent_directory: AgentDirectory | None = None,
) -> PolicySet:
    """Load and compile a policy from YAML text. See :func:`load_policy`.

    Raises:
        ConfigurationError: As for :func:`load_policy`, prefixed with ``source``.
    """
    raw = _parse_yaml(text, source)
    return _compile(raw, source, expected_trust_domain, replay_store, agent_directory)


def _read(path: Path, label: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raise ConfigurationError(f"{label}: policy file is not valid UTF-8") from None
    except OSError:
        raise ConfigurationError(f"{label}: cannot read policy file") from None


def _parse_yaml(text: str, label: str) -> object:
    try:
        root = yaml.compose(text, Loader=yaml.SafeLoader)
        if root is not None:
            _reject_duplicate_keys(root, label, set())
        return yaml.safe_load(text)
    except yaml.MarkedYAMLError as exc:
        # The parser's own message can quote source text, so report only the position.
        mark = exc.problem_mark or exc.context_mark
        where = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        raise ConfigurationError(f"{label}: invalid YAML{where}") from None
    except yaml.YAMLError:
        raise ConfigurationError(f"{label}: invalid YAML") from None


def _reject_duplicate_keys(node: yaml.Node, label: str, visited: set[int]) -> None:
    # Aliases share nodes; visit each once so an alias bomb cannot make this exponential.
    if id(node) in visited:
        return
    visited.add(id(node))
    if isinstance(node, yaml.MappingNode):
        seen: set[tuple[str, str]] = set()
        for key_node, value_node in node.value:
            if isinstance(key_node, yaml.ScalarNode):
                key = (key_node.tag, key_node.value)
                if key in seen:
                    raise ConfigurationError(
                        f"{label}: duplicate key '{key_node.value}' "
                        f"at line {key_node.start_mark.line + 1}"
                    )
                seen.add(key)
            _reject_duplicate_keys(key_node, label, visited)
            _reject_duplicate_keys(value_node, label, visited)
    elif isinstance(node, yaml.SequenceNode):
        for item in node.value:
            _reject_duplicate_keys(item, label, visited)


def _compile(
    raw: object,
    label: str,
    expected_trust_domain: str | None,
    replay_store: ReplayStore | None,
    agent_directory: AgentDirectory | None,
) -> PolicySet:
    if not isinstance(raw, Mapping):
        raise ConfigurationError(f"{label}: the policy document must be a mapping")
    # Check the version first: a document for another version should say so, not report its
    # new keys as unknown.
    version = raw.get("version")
    if isinstance(version, int) and not isinstance(version, bool):
        check_version(version, label)
    try:
        document = PolicyDocument.model_validate(dict(raw))
    except ValidationError as exc:
        raise ConfigurationError(f"{label}: {_describe(exc)}") from None
    return compile_policy(
        document,
        source=label,
        expected_trust_domain=expected_trust_domain,
        replay_store=replay_store,
        agent_directory=agent_directory,
    )


def _describe(exc: ValidationError) -> str:
    errors = exc.errors(include_url=False, include_input=False, include_context=False)
    described = [_describe_one(error) for error in errors[:_MAX_REPORTED_ERRORS]]
    if len(errors) > _MAX_REPORTED_ERRORS:
        described.append(f"and {len(errors) - _MAX_REPORTED_ERRORS} more")
    return "; ".join(described)


def _describe_one(error: ErrorDetails) -> str:
    message = _MESSAGES.get(error["type"], error["msg"]).removeprefix("Value error, ")
    return f"{_location(error['loc'])}: {message}"


def _location(loc: tuple[int | str, ...]) -> str:
    location = ""
    for part in loc:
        if isinstance(part, int):
            location += f"[{part}]"
        else:
            location += f".{part}" if location else part
    return location or "<document>"
