from __future__ import annotations

import pytest

from pytrat.agents import AgentMode, AgentRecord, InMemoryAgentStore, agent_mode, resolve_agent
from pytrat.core import AuthorizationError, ReasonCode, TokenError


def test_autonomous_mode_forbids_act() -> None:
    """agent-profile-03 §3.2.2: client-credentials Txn-Tokens MUST NOT contain act."""
    assert agent_mode(act=None, client_credentials=True) is AgentMode.AUTONOMOUS
    with pytest.raises(AuthorizationError) as excinfo:
        agent_mode(act={"sub": "agent"}, client_credentials=True)
    assert excinfo.value.reason is ReasonCode.ISSUANCE_NOT_AUTHORIZED


def test_subject_initiated_mode() -> None:
    """agent-profile-03 §3.2.1: delegated flows may carry act."""
    assert agent_mode(act={"sub": "a"}, client_credentials=False) is AgentMode.SUBJECT_INITIATED
    assert agent_mode(act=None, client_credentials=False) is AgentMode.SUBJECT_INITIATED


def test_act_sub_has_priority(
    store: InMemoryAgentStore, external: AgentRecord, internal: AgentRecord
) -> None:
    """agent-profile-03 §3.5.1: act.sub, then store lookup, then client_id, in that order."""
    resolved = resolve_agent(store, act={"sub": external.id}, client_id=external.client_id)
    assert resolved == external


def test_client_id_fallback(store: InMemoryAgentStore, internal: AgentRecord) -> None:
    """agent-profile-03 §3.6.1: client_id resolves a registered agent."""
    assert resolve_agent(store, act=None, client_id=internal.client_id) == internal


def test_unregistered_caller_is_not_an_agent(store: InMemoryAgentStore) -> None:
    """agent-profile-03 §3.6.1 step 4: non-agents get no agentic_ctx."""
    assert resolve_agent(store, act=None, client_id="plain-service") is None
    assert resolve_agent(store, act=None, client_id=None) is None
    assert resolve_agent(store, act={"sub": "unknown"}, client_id=None) is None
    assert resolve_agent(store, act={"sub": "unknown"}, client_id="plain-service") is None


def test_unregistered_actor_cannot_borrow_another_agents_client_id(
    store: InMemoryAgentStore, internal: AgentRecord
) -> None:
    """PyTraT profile: act.sub unregistered + client_id of a different agent is denied."""
    with pytest.raises(AuthorizationError) as excinfo:
        resolve_agent(store, act={"sub": "rogue"}, client_id=internal.client_id)
    assert excinfo.value.reason is ReasonCode.AGENT_UNVERIFIED


def test_actor_matching_client_agent_by_id_is_accepted() -> None:
    rec = AgentRecord(
        id="agent-1",
        name="n",
        owner="o",
        assurance_level="low",
        version="1",
        provenance="p",
        client_id="client-1",
    )
    store = InMemoryAgentStore([rec])
    assert resolve_agent(store, act={"sub": "agent-1"}, client_id="other") == rec


@pytest.mark.parametrize("act", [{}, {"sub": ""}, {"sub": 3}])
def test_malformed_act_is_rejected(store: InMemoryAgentStore, act: dict[str, object]) -> None:
    with pytest.raises(TokenError) as excinfo:
        resolve_agent(store, act=act, client_id=None)
    assert excinfo.value.reason is ReasonCode.CLAIM_INVALID
