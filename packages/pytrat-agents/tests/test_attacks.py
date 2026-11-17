"""Attack scenarios against the agent profile, named for the attack."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from pytrat.agents import (
    AgentLimits,
    AgentRecord,
    AgentRequirements,
    AssuranceOrdering,
    InMemoryAgentStore,
    ToolInvocation,
    ToolResultBlockedError,
    ToolRuntime,
    assert_replacement_attenuates,
    check_agent_requirements,
    initial_agentic_ctx,
    next_agentic_ctx,
    plan_agent_replacement,
    resolve_agent,
)
from pytrat.core import (
    AuthorizationError,
    EventType,
    MemorySink,
    ReasonCode,
    TransactionClaims,
    VerifiedToken,
    parse_claims,
)
from pytrat.core.testing import TokenFactory

pytestmark = pytest.mark.security


def _issue(agent: AgentRecord, ordering: AssuranceOrdering) -> TransactionClaims:
    ctx = initial_agentic_ctx(agent, ordering=ordering, include_assurance=True)
    return parse_claims(
        {
            "aud": "trust-domain.example",
            "txn": "txn-attack",
            "sub": "user:alice",
            "scope": "billing.process",
            "req_wl": "apigateway",
            "iat": 1,
            "exp": 61,
            "act": {"sub": agent.id},
            "agentic_ctx": ctx.model_dump(mode="json", exclude_none=True),
        }
    )


def _replace(
    current: TransactionClaims, agent: AgentRecord | None, limits: AgentLimits, workload: str
) -> TransactionClaims:
    plan = plan_agent_replacement(current, agent, workload, None, limits)
    return parse_claims({**current.to_payload(), **plan.to_claims()})


def test_low_assurance_external_agent_cannot_launder_through_high_assurance_agent(
    store: InMemoryAgentStore,
    external: AgentRecord,
    internal: AgentRecord,
    ordering: AssuranceOrdering,
    limits: AgentLimits,
) -> None:
    """agent-profile-03 §4.2, §5.9: a "low" 3P originator stays "low" behind a "high" 1P agent."""
    originator = resolve_agent(store, act={"sub": external.id}, client_id=external.client_id)
    assert originator == external
    first = _issue(originator, ordering)
    laundered = _replace(first, internal, limits, "1p-billing")
    assert laundered.agentic_ctx is not None
    assert laundered.agentic_ctx.chain_metadata.min_assurance_level == "low"
    assert laundered.agentic_ctx.originator.id == external.id
    assert laundered.act == first.act

    high_only = AgentRequirements(minimum_assurance="high")
    with pytest.raises(AuthorizationError) as excinfo:
        check_agent_requirements(laundered, high_only, ordering, store)
    assert excinfo.value.reason is ReasonCode.AGENT_ASSURANCE_INSUFFICIENT

    # A TTS bug or a forged plan that raised the level is caught by the attenuation oracle.
    forged_ctx = laundered.agentic_ctx.model_dump(mode="json")
    forged_ctx["chain_metadata"]["min_assurance_level"] = "high"
    forged = parse_claims({**laundered.to_payload(), "agentic_ctx": forged_ctx})
    with pytest.raises(AuthorizationError) as forged_exc:
        assert_replacement_attenuates(first, forged, limits)
    assert forged_exc.value.reason is ReasonCode.REPLACEMENT_WIDENS_AUTHORIZATION


def test_hop_limit_cannot_be_exceeded(
    external: AgentRecord, internal: AgentRecord, medium: AgentRecord, ordering: AssuranceOrdering
) -> None:
    """agent-profile-03 §4.2.3, §5.12: exceeding the threshold MUST reject the replacement."""
    limits = AgentLimits(max_hops=3, ordering=ordering)
    token = _issue(external, ordering)
    token = _replace(token, internal, limits, "w1")
    token = _replace(token, None, limits, "w2")  # non-agent hops do not reset or bypass
    token = _replace(token, medium, limits, "w3")
    assert token.agentic_ctx is not None
    assert token.agentic_ctx.chain_metadata.hop_count == 3
    for agent in (internal, medium, external):
        with pytest.raises(AuthorizationError) as excinfo:
            _replace(token, agent, limits, "w4")
        assert excinfo.value.reason is ReasonCode.AGENT_HOP_LIMIT_EXCEEDED
    # A resource enforcing a tighter limit rejects the over-long chain too.
    with pytest.raises(AuthorizationError) as rs_exc:
        check_agent_requirements(token, AgentRequirements(maximum_hops=2), ordering, None)
    assert rs_exc.value.reason is ReasonCode.AGENT_HOP_LIMIT_EXCEEDED
    # Lowering the limit below an existing chain blocks even non-agent replacement.
    with pytest.raises(AuthorizationError):
        _replace(token, None, AgentLimits(max_hops=2, ordering=ordering), "w5")


def test_non_agent_replacement_does_not_mutate_agentic_ctx(
    external: AgentRecord, internal: AgentRecord, ordering: AssuranceOrdering, limits: AgentLimits
) -> None:
    """agent-profile-03 §3.3.2: agentic_ctx MUST be carried forward without modification."""
    token = _replace(_issue(external, ordering), internal, limits, "1p")
    before = token.agentic_ctx
    for workload in ("ledger", "notifications", "audit"):
        token = _replace(token, None, limits, workload)
        assert token.agentic_ctx == before
    assert next_agentic_ctx(before, None, limits) is before


def test_session_id_does_not_change_issuance_or_replacement_outcome(
    external: AgentRecord, internal: AgentRecord, ordering: AssuranceOrdering, limits: AgentLimits
) -> None:
    """agent-profile-03 §5.15: session_id MUST NOT influence authorization decisions."""
    current = initial_agentic_ctx(
        external, session_id="sess-3p", ordering=ordering, include_assurance=True
    )
    outcomes = {
        next_agentic_ctx(current, internal, limits, session_id=session).chain_metadata  # type: ignore[union-attr]
        for session in (None, "sess-root", "sess-admin-override")
    }
    assert len(outcomes) == 1


def test_tool_result_containing_token_is_blocked(
    factory: TokenFactory,
    mint_verified: Callable[..., VerifiedToken],
    store: InMemoryAgentStore,
    internal: AgentRecord,
) -> None:
    """agent-profile-03 §3.7: Txn-Tokens MUST NOT appear in the LLM's context window.

    A downstream service echoes a token (its own, or another one) back in its response.
    """
    sink = MemorySink()
    token = mint_verified()
    runtime = ToolRuntime(
        agent=internal,
        token_provider=lambda invocation: token,
        store=store,
        audit=sink,
    )
    echoed = factory.mint(scope="billing.read admin")

    @runtime.protected_tool(scope="billing.read", resource="billing-api")
    def fetch_invoice(invoice_id: str) -> dict[str, object]:
        return {"invoice": invoice_id, "debug": {"headers": [f"Txn-Token: {echoed}"]}}

    with pytest.raises(ToolResultBlockedError):
        fetch_invoice(invoice_id="inv-1")
    assert sink.of_type(EventType.AUTHORIZATION_DENIED)[-1].reason_code is (
        ReasonCode.TOOL_RESULT_BLOCKED
    )


def test_llm_tool_specs_expose_no_credential_operations(
    mint_verified: Callable[..., VerifiedToken], store: InMemoryAgentStore, internal: AgentRecord
) -> None:
    """agent-profile-03 §3.7, §5.16: token exchange MUST NOT be exposed as a tool."""
    token = mint_verified()
    seen: list[ToolInvocation] = []

    def provider(invocation: ToolInvocation) -> VerifiedToken:
        seen.append(invocation)
        return token

    runtime = ToolRuntime(agent=internal, token_provider=provider, store=store, audit=MemorySink())

    @runtime.protected_tool(scope="billing.read", resource="billing-api")
    def get_invoice(invoice_id: str) -> str:
        """Fetch an invoice."""
        return invoice_id

    @runtime.protected_tool(scope="billing.read", resource="billing-api")
    async def list_invoices(limit: int = 10) -> list[str]:
        """List invoices."""
        return []

    specs = runtime.tool_specs()
    assert {spec.name for spec in specs} == {"get_invoice", "list_invoices"}
    forbidden = ("exchange", "replace", "token", "credential", "secret", "txn")
    for spec in specs:
        rendered = f"{spec.name} {spec.description} {spec.parameters}".lower()
        assert not any(word in rendered for word in forbidden), spec
    # The runtime itself offers no public credential operation the model could be routed to.
    public = {name for name in dir(runtime) if not name.startswith("_")}
    assert public == {"acall", "call", "protected_tool", "tool_specs"}
    # Model-controlled arguments never reach the token provider (§3.7).
    get_invoice(invoice_id="inv-1; scope=admin")
    assert seen[-1] == ToolInvocation(
        tool="get_invoice", resource="billing-api", scope=seen[-1].scope
    )
    assert "inv-1" not in repr(seen[-1])
