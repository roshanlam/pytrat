from __future__ import annotations

from collections.abc import Callable

import pytest

from pytrat.agents import (
    AgentLimits,
    AgentRecord,
    AssuranceOrdering,
    append_workload,
    assert_replacement_attenuates,
    initial_agentic_ctx,
    next_agentic_ctx,
    plan_agent_replacement,
    strip_for_egress,
)
from pytrat.core import (
    AgenticContext,
    AuthorizationError,
    ConfigurationError,
    ReasonCode,
    Scope,
    TransactionClaims,
    parse_claims,
)

type Claims = Callable[..., TransactionClaims]
type Ctx = Callable[..., dict[str, object]]


def _ctx(payload: dict[str, object]) -> AgenticContext:
    return AgenticContext.model_validate(payload)


# ---------------------------------------------------------------- AgentLimits


@pytest.mark.parametrize("max_hops", [0, -1, 10_001, True])
def test_limits_reject_bad_max_hops(max_hops: int) -> None:
    with pytest.raises(ConfigurationError):
        AgentLimits(max_hops=max_hops)


def test_limits_reject_unknown_default_assurance() -> None:
    with pytest.raises(ConfigurationError):
        AgentLimits(max_hops=3, default_assurance="ultra")
    custom = AssuranceOrdering(("bronze", "gold"))
    assert AgentLimits(max_hops=3, ordering=custom, default_assurance="bronze").max_hops == 3


# ---------------------------------------------------------------- initial issuance


def test_initial_ctx_hop_one_and_originator_is_proximate(
    external: AgentRecord, ordering: AssuranceOrdering
) -> None:
    """agent-profile-03 §3.5.1: hop_count is 1 at issuance; originator == proximate."""
    ctx = initial_agentic_ctx(
        external,
        session_id="sess-1",
        ordering=ordering,
        include_assurance=True,
        attr_store_ref="https://registry.example/agents",
    )
    assert ctx.chain_metadata.hop_count == 1
    assert ctx.originator == ctx.proximate_agent
    assert ctx.originator.id == external.id
    assert ctx.originator.session_id == "sess-1"
    assert ctx.chain_metadata.min_assurance_level == "low"
    assert ctx.attr_store_ref == "https://registry.example/agents"


def test_initial_ctx_without_assurance(internal: AgentRecord, ordering: AssuranceOrdering) -> None:
    """agent-profile-03 §3.5.1: min_assurance_level is OPTIONAL."""
    ctx = initial_agentic_ctx(internal, ordering=ordering, include_assurance=False)
    assert ctx.chain_metadata.min_assurance_level is None
    assert ctx.proximate_agent.session_id is None


# ---------------------------------------------------------------- next_agentic_ctx


def test_agent_hop_updates_proximate_and_increments(
    ctx_payload: Ctx, internal: AgentRecord, limits: AgentLimits
) -> None:
    """agent-profile-03 §3.3.1: proximate set to new agent, hop_count + 1."""
    current = _ctx(ctx_payload(session_id="sess-3p", attr_store_ref="https://r.example"))
    new = next_agentic_ctx(current, internal, limits, session_id="sess-1p")
    assert new is not None
    assert new.proximate_agent.id == internal.id
    assert new.proximate_agent.session_id == "sess-1p"
    assert new.chain_metadata.hop_count == 2
    # agent-profile-03 §4.2.1 / §3.3.1: originator (incl. session_id) is preserved.
    assert new.originator == current.originator
    assert new.originator.session_id == "sess-3p"
    assert new.attr_store_ref == "https://r.example"


def test_agent_hop_without_session_clears_previous_session(
    ctx_payload: Ctx, internal: AgentRecord, limits: AgentLimits
) -> None:
    """agent-profile-03 §3.5.1: proximate session_id always reflects the current agent."""
    current = _ctx(ctx_payload(session_id="sess-3p"))
    new = next_agentic_ctx(current, internal, limits)
    assert new is not None
    assert new.proximate_agent.session_id is None


def test_assurance_takes_minimum(
    ctx_payload: Ctx, internal: AgentRecord, external: AgentRecord, limits: AgentLimits
) -> None:
    """agent-profile-03 §3.3.1, §4.2: min of existing and new agent's level."""
    high = _ctx(ctx_payload(min_assurance_level="high"))
    lowered = next_agentic_ctx(high, external, limits)
    assert lowered is not None
    assert lowered.chain_metadata.min_assurance_level == "low"
    low = _ctx(ctx_payload(min_assurance_level="low"))
    kept = next_agentic_ctx(low, internal, limits)
    assert kept is not None
    assert kept.chain_metadata.min_assurance_level == "low"


def test_absent_assurance_uses_default(
    ctx_payload: Ctx, internal: AgentRecord, limits: AgentLimits, ordering: AssuranceOrdering
) -> None:
    """PyTraT profile P6: an absent level is treated as default_assurance (lowest)."""
    current = _ctx(ctx_payload(min_assurance_level=None))
    new = next_agentic_ctx(current, internal, limits)
    assert new is not None
    assert new.chain_metadata.min_assurance_level == ordering.lowest


def test_unknown_assurance_in_token_counts_as_lowest(
    ctx_payload: Ctx, internal: AgentRecord, limits: AgentLimits
) -> None:
    current = _ctx(ctx_payload(min_assurance_level="cosmic"))
    new = next_agentic_ctx(current, internal, limits)
    assert new is not None
    assert new.chain_metadata.min_assurance_level == "unverified"


def test_non_agent_returns_current_unchanged(ctx_payload: Ctx, limits: AgentLimits) -> None:
    """agent-profile-03 §3.3.2: agentic_ctx carried forward without modification."""
    current = _ctx(ctx_payload(hop_count=3))
    assert next_agentic_ctx(current, None, limits) is current
    assert next_agentic_ctx(None, None, limits) is None


def test_hop_limit_on_agent_hop(ctx_payload: Ctx, internal: AgentRecord) -> None:
    """agent-profile-03 §4.2.3: exceeding the threshold MUST reject the replacement."""
    limits = AgentLimits(max_hops=2)
    at_limit = next_agentic_ctx(_ctx(ctx_payload(hop_count=1)), internal, limits)
    assert at_limit is not None
    assert at_limit.chain_metadata.hop_count == 2
    with pytest.raises(AuthorizationError) as excinfo:
        next_agentic_ctx(_ctx(ctx_payload(hop_count=2)), internal, limits)
    assert excinfo.value.reason is ReasonCode.AGENT_HOP_LIMIT_EXCEEDED


def test_hop_limit_on_non_agent_hop(ctx_payload: Ctx) -> None:
    """agent-profile-03 §5.12: an over-limit chain is rejected on any replacement."""
    with pytest.raises(AuthorizationError) as excinfo:
        next_agentic_ctx(_ctx(ctx_payload(hop_count=4)), None, AgentLimits(max_hops=3))
    assert excinfo.value.reason is ReasonCode.AGENT_HOP_LIMIT_EXCEEDED


def test_agent_without_context_is_denied_by_default(
    internal: AgentRecord, limits: AgentLimits
) -> None:
    """PyTraT profile: an agent replacing a token without agentic_ctx is denied by default."""
    with pytest.raises(AuthorizationError) as excinfo:
        next_agentic_ctx(None, internal, limits)
    assert excinfo.value.reason is ReasonCode.AGENT_CONTEXT_MISSING


def test_agent_without_context_starts_chain_when_allowed(internal: AgentRecord) -> None:
    """PyTraT profile: with require_replacement=False the agent becomes the originator."""
    limits = AgentLimits(max_hops=3, require_replacement=False)
    ctx = next_agentic_ctx(None, internal, limits, session_id="s")
    assert ctx is not None
    assert ctx.originator.id == ctx.proximate_agent.id == internal.id
    assert ctx.chain_metadata.hop_count == 1
    # Capped by default_assurance: the earlier, non-agent part was never assessed.
    assert ctx.chain_metadata.min_assurance_level == "unverified"


# ---------------------------------------------------------------- req_wl


def test_append_workload() -> None:
    """agent-profile-03 §3.3.1: req_wl is appended with a comma."""
    assert append_workload("apigateway", "billing") == "apigateway,billing"


@pytest.mark.parametrize("workload", ["", "a,b"])
def test_append_workload_rejects_ambiguous_ids(workload: str) -> None:
    """PyTraT profile P5: workload identifiers containing ',' are rejected."""
    with pytest.raises(AuthorizationError) as excinfo:
        append_workload("apigateway", workload)
    assert excinfo.value.reason is ReasonCode.ISSUANCE_NOT_AUTHORIZED


# ---------------------------------------------------------------- plan


def test_plan_for_agent_hop(claims: Claims, internal: AgentRecord, limits: AgentLimits) -> None:
    """agent-profile-03 §3.3.1, §4.2.1: immutables copied, req_wl appended, ctx updated."""
    current = claims()
    plan = plan_agent_replacement(
        current, internal, "billing-wl", Scope.of("billing.read"), limits, session_id="s1"
    )
    assert (plan.txn, plan.sub, plan.aud, plan.act) == (
        current.txn,
        current.sub,
        current.aud,
        current.act,
    )
    assert plan.scope == Scope.of("billing.read")
    assert plan.req_wl == "apigateway,billing-wl"
    assert plan.requester_is_agent
    assert plan.agentic_ctx is not None
    assert plan.agentic_ctx.chain_metadata.hop_count == 2
    payload = plan.to_claims()
    assert payload["act"] == {"sub": "3p-assistant-ext-99"}
    assert payload["scope"] == "billing.read"
    assert payload["agentic_ctx"] == {
        "originator": {"id": "3p-assistant-ext-99"},
        "proximate_agent": {"id": internal.id, "session_id": "s1"},
        "chain_metadata": {"hop_count": 2, "min_assurance_level": "low"},
    }


def test_plan_keeps_scope_when_none_requested(
    claims: Claims, internal: AgentRecord, limits: AgentLimits
) -> None:
    current = claims()
    assert plan_agent_replacement(current, internal, "w", None, limits).scope == current.scope


def test_plan_rejects_scope_widening(
    claims: Claims, internal: AgentRecord, limits: AgentLimits
) -> None:
    """txn-tokens-11 §13.15; agent-profile-03 §3.3.1: scope can only be attenuated."""
    with pytest.raises(AuthorizationError) as excinfo:
        plan_agent_replacement(claims(), internal, "w", Scope.of("billing.read", "admin"), limits)
    assert excinfo.value.reason is ReasonCode.REPLACEMENT_WIDENS_AUTHORIZATION


def test_plan_non_agent_with_context_appends(claims: Claims, limits: AgentLimits) -> None:
    """agent-profile-03 §3.3.2: ctx unchanged; PyTraT profile P5: req_wl still appended."""
    current = claims()
    plan = plan_agent_replacement(current, None, "ledger", None, limits)
    assert plan.agentic_ctx is current.agentic_ctx
    assert plan.req_wl == "apigateway,ledger"
    assert not plan.requester_is_agent


def test_plan_without_any_agent_uses_base_rules(claims: Claims, limits: AgentLimits) -> None:
    """txn-tokens-11 §9.2: without agentic_ctx, req_wl names the requesting workload."""
    plan = plan_agent_replacement(claims(agentic_ctx=None, act=None), None, "ledger", None, limits)
    assert plan.agentic_ctx is None
    assert plan.req_wl == "ledger"
    assert "act" not in plan.to_claims()
    assert "agentic_ctx" not in plan.to_claims()
    with pytest.raises(AuthorizationError):
        plan_agent_replacement(claims(agentic_ctx=None), None, "a,b", None, limits)


def test_plan_agent_on_token_without_context_is_denied(
    claims: Claims, internal: AgentRecord, limits: AgentLimits
) -> None:
    with pytest.raises(AuthorizationError) as excinfo:
        plan_agent_replacement(claims(agentic_ctx=None), internal, "w", None, limits)
    assert excinfo.value.reason is ReasonCode.AGENT_CONTEXT_MISSING


# ---------------------------------------------------------------- attenuation oracle


def _replace(current: TransactionClaims, **changes: object) -> TransactionClaims:
    payload = current.to_payload()
    payload.update(changes)
    for name in [key for key, value in changes.items() if value is None]:
        payload.pop(name)
    return parse_claims(payload)


def test_attenuation_accepts_planned_replacement(
    claims: Claims, internal: AgentRecord, limits: AgentLimits
) -> None:
    current = claims()
    plan = plan_agent_replacement(current, internal, "w", Scope.of("billing.read"), limits)
    replacement = _replace(current, **plan.to_claims())
    assert_replacement_attenuates(current, replacement, limits)


@pytest.mark.parametrize(
    ("changes", "detail"),
    [
        ({"txn": "other"}, "txn"),
        ({"sub": "user:mallory"}, "txn"),
        ({"aud": "other-domain"}, "txn"),
        ({"act": {"sub": "1p-billing-svc-v2"}}, "act"),
        ({"act": None}, "act"),
        ({"scope": "billing.read admin"}, "scope"),
        ({"agentic_ctx": None}, "dropped"),
    ],
)
def test_attenuation_rejects_widening(
    claims: Claims, limits: AgentLimits, changes: dict[str, object], detail: str
) -> None:
    """agent-profile-03 §3.3.1, §5.2, §5.3: immutables never change; scope never widens."""
    current = claims()
    with pytest.raises(AuthorizationError) as excinfo:
        assert_replacement_attenuates(current, _replace(current, **changes), limits)
    assert excinfo.value.reason is ReasonCode.REPLACEMENT_WIDENS_AUTHORIZATION
    assert detail in excinfo.value.detail


@pytest.mark.parametrize(
    ("ctx_changes", "detail"),
    [
        ({"originator": "someone-else"}, "originator"),
        ({"hop_count": 1, "proximate": "x"}, "hop_count"),
        ({"min_assurance_level": "high"}, "min_assurance_level"),
    ],
)
def test_attenuation_rejects_chain_widening(
    claims: Claims,
    ctx_payload: Ctx,
    limits: AgentLimits,
    ctx_changes: dict[str, object],
    detail: str,
) -> None:
    """agent-profile-03 §4.2.1, §5.9: originator fixed, hops rise, assurance never rises."""
    current = claims(agentic_ctx=ctx_payload(hop_count=2, min_assurance_level="medium"))
    base: dict[str, object] = {"hop_count": 2, "min_assurance_level": "medium"}
    replacement = _replace(current, agentic_ctx=ctx_payload(**{**base, **ctx_changes}))
    with pytest.raises(AuthorizationError) as excinfo:
        assert_replacement_attenuates(current, replacement, limits)
    assert detail in excinfo.value.detail


def test_attenuation_allows_tokens_without_context(claims: Claims, limits: AgentLimits) -> None:
    current = claims(agentic_ctx=None)
    assert_replacement_attenuates(current, current, limits)


# ---------------------------------------------------------------- egress


def test_strip_for_egress_removes_attr_store_ref(ctx_payload: Ctx) -> None:
    """agent-profile-03 §5.13: the TTS MUST strip attr_store_ref on egress."""
    ctx = _ctx(ctx_payload(attr_store_ref="https://registry.internal/agents"))
    stripped = strip_for_egress(ctx)
    assert stripped is not None
    assert stripped.attr_store_ref is None
    assert stripped.originator == ctx.originator
    assert stripped.chain_metadata == ctx.chain_metadata
    plain = _ctx(ctx_payload())
    assert strip_for_egress(plain) is plain
    assert strip_for_egress(None) is None
