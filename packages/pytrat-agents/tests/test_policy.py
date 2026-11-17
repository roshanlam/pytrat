from __future__ import annotations

from collections.abc import Callable

import pytest

from pytrat.agents import (
    AgentRecord,
    AgentRequirements,
    AssuranceOrdering,
    InMemoryAgentStore,
    check_agent_requirements,
)
from pytrat.core import (
    AuthorizationError,
    ConfigurationError,
    DependencyError,
    ReasonCode,
    TransactionClaims,
)

type Claims = Callable[..., TransactionClaims]
type Ctx = Callable[..., dict[str, object]]


def test_empty_requirements_pass_any_token(claims: Claims, ordering: AssuranceOrdering) -> None:
    check_agent_requirements(claims(), AgentRequirements(), ordering, None)
    check_agent_requirements(claims(agentic_ctx=None), AgentRequirements(), ordering, None)


def test_hop_limit(claims: Claims, ctx_payload: Ctx, ordering: AssuranceOrdering) -> None:
    """agent-profile-03 §3.5.1: RS evaluates hop_count against deployment limits."""
    requirements = AgentRequirements(maximum_hops=2)
    check_agent_requirements(
        claims(agentic_ctx=ctx_payload(hop_count=2)), requirements, ordering, None
    )
    with pytest.raises(AuthorizationError) as excinfo:
        check_agent_requirements(
            claims(agentic_ctx=ctx_payload(hop_count=3)), requirements, ordering, None
        )
    assert excinfo.value.reason is ReasonCode.AGENT_HOP_LIMIT_EXCEEDED


def test_hop_limit_alone_accepts_tokens_without_agents(
    claims: Claims, ordering: AssuranceOrdering
) -> None:
    requirements = AgentRequirements(maximum_hops=1)
    check_agent_requirements(claims(agentic_ctx=None), requirements, ordering, None)


@pytest.mark.parametrize(
    "requirements",
    [
        AgentRequirements(require_agent_context=True),
        AgentRequirements(minimum_assurance="low"),
        AgentRequirements(require_verified_agent=True),
        AgentRequirements(allowed_originators=frozenset({"x"})),
    ],
)
def test_missing_context_is_denied(
    claims: Claims, ordering: AssuranceOrdering, requirements: AgentRequirements
) -> None:
    """PyTraT profile: a check that needs agentic_ctx fails closed without it."""
    with pytest.raises(AuthorizationError) as excinfo:
        check_agent_requirements(claims(agentic_ctx=None), requirements, ordering, None)
    assert excinfo.value.reason is ReasonCode.AGENT_CONTEXT_MISSING


def test_allowed_originators(claims: Claims, ordering: AssuranceOrdering) -> None:
    """agent-profile-03 §3.5.1: RS SHOULD use originator.id for originator policies."""
    ok = AgentRequirements(allowed_originators=frozenset({"3p-assistant-ext-99"}))
    check_agent_requirements(claims(), ok, ordering, None)
    with pytest.raises(AuthorizationError) as excinfo:
        check_agent_requirements(
            claims(), AgentRequirements(allowed_originators=frozenset({"other"})), ordering, None
        )
    assert excinfo.value.reason is ReasonCode.AGENT_NOT_ALLOWED


@pytest.mark.parametrize(
    ("level", "required", "allowed"),
    [("high", "medium", True), ("medium", "medium", True), ("low", "medium", False)],
)
def test_minimum_assurance(  # noqa: PLR0917 - fixtures plus parameters
    claims: Claims,
    ctx_payload: Ctx,
    ordering: AssuranceOrdering,
    level: str,
    required: str,
    allowed: bool,
) -> None:
    """agent-profile-03 §4.2: RS evaluates min_assurance_level from the token."""
    token = claims(agentic_ctx=ctx_payload(min_assurance_level=level))
    requirements = AgentRequirements(minimum_assurance=required)
    if allowed:
        check_agent_requirements(token, requirements, ordering, None)
    else:
        with pytest.raises(AuthorizationError) as excinfo:
            check_agent_requirements(token, requirements, ordering, None)
        assert excinfo.value.reason is ReasonCode.AGENT_ASSURANCE_INSUFFICIENT


@pytest.mark.parametrize("level", [None, "cosmic"])
def test_absent_or_unknown_assurance_never_satisfies(
    claims: Claims, ctx_payload: Ctx, ordering: AssuranceOrdering, level: str | None
) -> None:
    token = claims(agentic_ctx=ctx_payload(min_assurance_level=level))
    with pytest.raises(AuthorizationError) as excinfo:
        check_agent_requirements(
            token, AgentRequirements(minimum_assurance="unverified"), ordering, None
        )
    assert excinfo.value.reason is ReasonCode.AGENT_ASSURANCE_INSUFFICIENT


def test_unknown_required_level_is_configuration_error(
    claims: Claims, ordering: AssuranceOrdering
) -> None:
    with pytest.raises(ConfigurationError):
        check_agent_requirements(
            claims(), AgentRequirements(minimum_assurance="ultra"), ordering, None
        )


def test_verified_agent(
    claims: Claims,
    ctx_payload: Ctx,
    ordering: AssuranceOrdering,
    store: InMemoryAgentStore,
    internal: AgentRecord,
) -> None:
    """agent-profile-03 §3.5.4: proximate_agent.id is the store lookup key."""
    requirements = AgentRequirements(require_verified_agent=True)
    token = claims(agentic_ctx=ctx_payload(proximate=internal.id))
    check_agent_requirements(token, requirements, ordering, store)


def test_unregistered_agent_is_rejected_when_verification_required(
    claims: Claims, ctx_payload: Ctx, ordering: AssuranceOrdering, store: InMemoryAgentStore
) -> None:
    """agent-profile-03 §3.6: a proximate agent absent from the store is unverified."""
    token = claims(agentic_ctx=ctx_payload(proximate="impostor-agent"))
    with pytest.raises(AuthorizationError) as excinfo:
        check_agent_requirements(
            token, AgentRequirements(require_verified_agent=True), ordering, store
        )
    assert excinfo.value.reason is ReasonCode.AGENT_UNVERIFIED


def test_verification_without_store_fails_closed(
    claims: Claims, ordering: AssuranceOrdering
) -> None:
    with pytest.raises(DependencyError) as excinfo:
        check_agent_requirements(
            claims(), AgentRequirements(require_verified_agent=True), ordering, None
        )
    assert excinfo.value.reason is ReasonCode.DEPENDENCY_UNAVAILABLE


class _BrokenStore:
    def __init__(self, error: Exception) -> None:
        self.error = error

    def get(self, agent_id: str) -> AgentRecord | None:
        raise self.error

    def by_client_id(self, client_id: str) -> AgentRecord | None:
        raise self.error


@pytest.mark.parametrize("error", [OSError("down"), DependencyError("down")])
def test_store_failure_fails_closed(
    claims: Claims, ordering: AssuranceOrdering, error: Exception
) -> None:
    with pytest.raises(DependencyError) as excinfo:
        check_agent_requirements(
            claims(), AgentRequirements(require_verified_agent=True), ordering, _BrokenStore(error)
        )
    assert excinfo.value.reason is ReasonCode.DEPENDENCY_UNAVAILABLE


def test_session_id_is_not_an_authorization_input(
    claims: Claims, ctx_payload: Ctx, ordering: AssuranceOrdering, store: InMemoryAgentStore
) -> None:
    """agent-profile-03 §3.5.1, §3.5.4, §5.15: session_id MUST NOT be an authorization input.

    Two tokens that differ only in session_id must get identical decisions, under every
    requirement, and the checker's signature has no session parameter.
    """
    import inspect

    assert "session" not in " ".join(inspect.signature(check_agent_requirements).parameters)
    assert not any("session" in name for name in AgentRequirements.__dataclass_fields__)

    variants = [
        AgentRequirements(),
        AgentRequirements(maximum_hops=1),
        AgentRequirements(minimum_assurance="low"),
        AgentRequirements(minimum_assurance="high"),
        AgentRequirements(require_verified_agent=True),
        AgentRequirements(allowed_originators=frozenset({"3p-assistant-ext-99"})),
    ]
    for requirements in variants:
        outcomes = set()
        for session in (None, "sess-admin", "sess-trusted-root", "x" * 200):
            token = claims(agentic_ctx=ctx_payload(session_id=session))
            try:
                check_agent_requirements(token, requirements, ordering, store)
                outcomes.add("allow")
            except AuthorizationError as exc:
                outcomes.add(exc.reason)
        assert len(outcomes) == 1, requirements
