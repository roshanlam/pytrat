"""Property tests: any sequence of replacements only attenuates the token.

agent-profile-03 §3.3.1, §3.3.2, §4.2, §4.2.1, §5.9; txn-tokens-11 §13.15.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from pytrat.agents import (
    DEFAULT_LEVELS,
    AgentLimits,
    AgentRecord,
    AssuranceOrdering,
    assert_replacement_attenuates,
    initial_agentic_ctx,
    plan_agent_replacement,
)
from pytrat.core import AuthorizationError, ReasonCode, Scope, TransactionClaims, parse_claims

ORDERING = AssuranceOrdering()
ALL_SCOPES = ("a.read", "a.write", "b.read", "b.write", "c.admin")


@dataclass(frozen=True)
class Step:
    agent_level: str | None  # None: the requester is not an agent
    scope: frozenset[str] | None  # None: keep the current scope
    session_id: str | None


def _agent(index: int, level: str) -> AgentRecord:
    return AgentRecord(
        id=f"agent-{index}",
        name="n",
        owner="o",
        assurance_level=level,
        version="1",
        provenance="p",
    )


def _initial(level: str, include_assurance: bool, act: bool) -> TransactionClaims:
    ctx = initial_agentic_ctx(
        _agent(0, level), ordering=ORDERING, include_assurance=include_assurance
    )
    payload: dict[str, object] = {
        "aud": "td.example",
        "txn": "txn-prop",
        "sub": "user:p",
        "scope": " ".join(ALL_SCOPES),
        "req_wl": "gateway",
        "iat": 1,
        "exp": 61,
        "agentic_ctx": ctx.model_dump(mode="json", exclude_none=True),
    }
    if act:
        payload["act"] = {"sub": "agent-0", "nested": {"k": [1, 2]}}
    return parse_claims(payload)


def _rank(level: str | None) -> int:
    return ORDERING.levels.index(level or DEFAULT_LEVELS[0])


steps = st.lists(
    st.builds(
        Step,
        agent_level=st.none() | st.sampled_from(DEFAULT_LEVELS),
        scope=st.none() | st.frozensets(st.sampled_from(ALL_SCOPES), min_size=1),
        session_id=st.none() | st.text(min_size=1, max_size=8),
    ),
    max_size=25,
)


def _apply(current: TransactionClaims, plan_claims: dict[str, object]) -> TransactionClaims:
    payload = current.to_payload()
    payload.update(plan_claims)
    return parse_claims(payload)


@settings(max_examples=300, deadline=None)
@given(
    initial_level=st.sampled_from(DEFAULT_LEVELS),
    include_assurance=st.booleans(),
    act=st.booleans(),
    sequence=steps,
)
def test_any_replacement_sequence_only_attenuates(
    initial_level: str, include_assurance: bool, act: bool, sequence: list[Step]
) -> None:
    """Scope and min_assurance_level never rise, hop_count rises by one per agent hop only, and
    originator, txn, sub, aud and act never change."""
    limits = AgentLimits(max_hops=100, ordering=ORDERING)
    first = _initial(initial_level, include_assurance, act)
    current = first
    assert first.agentic_ctx is not None
    for index, step in enumerate(sequence, start=1):
        requester = None if step.agent_level is None else _agent(index, step.agent_level)
        requested = None if step.scope is None else Scope(step.scope)
        widens = requested is not None and not requested.issubset(current.scope)
        if widens:
            with pytest.raises(AuthorizationError) as excinfo:
                plan_agent_replacement(current, requester, f"wl-{index}", requested, limits)
            assert excinfo.value.reason is ReasonCode.REPLACEMENT_WIDENS_AUTHORIZATION
            continue
        plan = plan_agent_replacement(
            current, requester, f"wl-{index}", requested, limits, session_id=step.session_id
        )
        nxt = _apply(current, plan.to_claims())
        assert_replacement_attenuates(current, nxt, limits)

        before, after = current.agentic_ctx, nxt.agentic_ctx
        assert before is not None
        assert after is not None
        assert nxt.scope.issubset(current.scope)
        # An absent min_assurance_level ranks as the default, which is the lowest level.
        assert _rank(after.chain_metadata.min_assurance_level) <= _rank(
            before.chain_metadata.min_assurance_level
        )
        expected = before.chain_metadata.hop_count + (1 if requester is not None else 0)
        assert after.chain_metadata.hop_count == expected
        if requester is None:
            assert after == before
        else:
            assert after.proximate_agent.id == requester.id
            # The chain minimum never exceeds the requesting agent's own level.
            assert _rank(after.chain_metadata.min_assurance_level) <= _rank(
                requester.assurance_level
            )
        assert after.originator == first.agentic_ctx.originator
        assert (nxt.txn, nxt.sub, nxt.aud, nxt.act) == (first.txn, first.sub, first.aud, first.act)
        # req_wl grows by exactly the requesting workload.
        assert nxt.requesting_workloads == (*current.requesting_workloads, f"wl-{index}")
        current = nxt


@settings(max_examples=200, deadline=None)
@given(
    max_hops=st.integers(min_value=1, max_value=8),
    agent_hops=st.lists(st.booleans(), max_size=20),
)
def test_hop_limit_holds_for_any_sequence(max_hops: int, agent_hops: list[bool]) -> None:
    """agent-profile-03 §4.2.3: no sequence produces a token above max_hops."""
    limits = AgentLimits(max_hops=max_hops, ordering=ORDERING)
    current = _initial("high", True, True)
    for index, is_agent in enumerate(agent_hops, start=1):
        assert current.agentic_ctx is not None
        hops = current.agentic_ctx.chain_metadata.hop_count
        requester = _agent(index, "medium") if is_agent else None
        if is_agent and hops == max_hops:
            with pytest.raises(AuthorizationError) as excinfo:
                plan_agent_replacement(current, requester, "wl", None, limits)
            assert excinfo.value.reason is ReasonCode.AGENT_HOP_LIMIT_EXCEEDED
            return
        current = _apply(
            current, plan_agent_replacement(current, requester, "wl", None, limits).to_claims()
        )
        assert current.agentic_ctx is not None
        assert current.agentic_ctx.chain_metadata.hop_count <= max_hops
