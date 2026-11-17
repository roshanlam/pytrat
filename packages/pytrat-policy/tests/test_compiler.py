from __future__ import annotations

import pytest

from pytrat.core import (
    AssuranceOrdering,
    ConfigurationError,
    ContextBinding,
    Derived,
    InMemoryReplayStore,
    ReasonCode,
    Scope,
)
from pytrat.policy import (
    AgentRequirements,
    CompiledPolicy,
    PolicyDocument,
    compile_policy,
)


def build_error(**arguments: object) -> ConfigurationError:
    arguments.setdefault("policy_id", "p")
    with pytest.raises(ConfigurationError) as info:
        CompiledPolicy.build(**arguments)  # type: ignore[arg-type]
    return info.value


def test_build_normalises_inputs() -> None:
    policy = CompiledPolicy.build(
        policy_id="p",
        allowed_scopes=["b", "a"],
        bind_context={"amount.minor": "amount_minor"},
        allowed_callers=iter(["svc"]),
    )
    assert policy.allowed_scopes == Scope.of("a", "b")
    assert policy.allowed_callers == frozenset({"svc"})
    assert policy.binding.fields == ("amount_minor",)
    assert policy.agents == AgentRequirements()
    assert policy.assurance == AssuranceOrdering()


def test_build_accepts_compiled_scope_and_binding() -> None:
    scope = Scope.of("s")
    binding = ContextBinding.compile(
        [Derived("amount", "amount_minor", lambda v: v, name="identity")]
    )
    policy = CompiledPolicy.build(policy_id="p", allowed_scopes=scope, bind_context=binding)
    assert policy.allowed_scopes is scope
    assert policy.binding is binding


def test_dependencies_do_not_affect_equality() -> None:
    first = CompiledPolicy.build(
        policy_id="p", allowed_scopes="s", single_use=True, replay_store=InMemoryReplayStore()
    )
    second = CompiledPolicy.build(
        policy_id="p", allowed_scopes="s", single_use=True, replay_store=InMemoryReplayStore()
    )
    assert first == second
    assert "replay_store" not in repr(first)


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        ({"policy_id": ""}, "policy_id: must not be empty"),
        ({}, "allowed_scopes: must not be empty when require_transaction is true"),
        ({"allowed_scopes": ""}, "allowed_scopes: must not be empty"),
        ({"allowed_scopes": "a  b"}, "allowed_scopes: contains a value that is not a valid"),
        ({"allowed_scopes": "s", "allowed_callers": "svc"}, "allowed_callers: must be a list"),
        ({"allowed_scopes": "s", "allowed_callers": [""]}, "allowed_callers: entries must be"),
        ({"allowed_scopes": "s", "bind_context": "amount"}, "bind_context: must be a list"),
        (
            {"require_transaction": False, "single_use": True},
            "single_use: requires require_transaction: true",
        ),
        (
            {"require_transaction": False, "agents": AgentRequirements(enabled=True)},
            "agents.enabled: requires require_transaction: true",
        ),
        (
            {
                "allowed_scopes": "s",
                "agents": AgentRequirements(enabled=True, minimum_assurance="high"),
                "assurance": AssuranceOrdering(("low", "medium")),
            },
            "agents.minimum_assurance: is not a level",
        ),
    ],
)
def test_build_rejects_invalid_policies(arguments: dict[str, object], expected: str) -> None:
    error = build_error(**arguments)
    assert expected in error.detail
    assert error.reason is ReasonCode.POLICY_INVALID


@pytest.mark.parametrize(
    "arguments",
    [
        {"allowed_scopes": "s", "single_use": True},
        {
            "allowed_scopes": "s",
            "agents": AgentRequirements(enabled=True, require_verified_agent=True),
        },
    ],
)
def test_build_fails_closed_without_dependencies(arguments: dict[str, object]) -> None:
    assert build_error(**arguments).reason is ReasonCode.DEPENDENCY_UNAVAILABLE


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        ({"maximum_hops": 3}, "agents.enabled: agent constraints are set"),
        ({"minimum_assurance": "low"}, "agents.enabled"),
        ({"require_chain_replacement": True}, "agents.enabled"),
        ({"require_agent_context": True}, "agents.enabled"),
        ({"require_verified_agent": True}, "agents.enabled"),
        ({"allowed_originators": frozenset({"a"})}, "agents.enabled"),
        ({"enabled": True, "maximum_hops": 0}, "agents.maximum_hops: must be a positive"),
        ({"enabled": True, "maximum_hops": True}, "agents.maximum_hops"),
        ({"enabled": True, "maximum_hops": "3"}, "agents.maximum_hops"),
        ({"enabled": True, "minimum_assurance": ""}, "agents.minimum_assurance: must not be"),
        ({"enabled": True, "allowed_originators": frozenset()}, "allowed_originators: must not"),
        ({"enabled": True, "allowed_originators": "planner"}, "allowed_originators: must be a"),
    ],
)
def test_agent_requirements_reject_invalid_values(
    arguments: dict[str, object], expected: str
) -> None:
    with pytest.raises(ConfigurationError) as info:
        AgentRequirements(**arguments)  # type: ignore[arg-type]
    assert expected in info.value.detail


def test_agent_requirements_normalise_originator_iterables() -> None:
    agents = AgentRequirements(enabled=True, allowed_originators=["a", "b"])  # type: ignore[arg-type]
    assert agents.allowed_originators == frozenset({"a", "b"})


def test_compile_policy_rejects_unsupported_version() -> None:
    document = PolicyDocument.model_validate(
        {
            "version": 7,
            "trust_domain": "t",
            "resources": [{"name": "a", "path": "/a", "method": "GET", "allowed_scopes": ["s"]}],
        }
    )
    with pytest.raises(ConfigurationError, match=r"policy\.yaml: version: unsupported"):
        compile_policy(document, source="policy.yaml")
