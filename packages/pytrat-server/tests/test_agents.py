"""Agent profile integration (agent-profile-03), delegated to pytrat.agents."""

from __future__ import annotations

import pytest
import yaml

from pytrat.core import EventType, ReasonCode

REGISTRY = {
    "agents": [
        {
            "id": "assistant-agent",
            "name": "Assistant",
            "owner": "team-a",
            "assurance_level": "high",
            "version": "1",
            "provenance": "sha256:aa",
            "client_id": "web-app",
        },
        {
            "id": "billing-agent",
            "name": "Billing",
            "owner": "team-b",
            "assurance_level": "medium",
            "version": "1",
            "provenance": "sha256:bb",
            "client_id": "billing-agent",
        },
        {
            "id": "auto-agent",
            "name": "Autonomous",
            "owner": "team-c",
            "assurance_level": "low",
            "version": "1",
            "provenance": "sha256:cc",
            "client_id": "auto-client",
        },
    ]
}


@pytest.fixture
def agent_tts(make_tts, tmp_path):
    def build(max_hops=5, **extra):
        (tmp_path / "agents.yaml").write_text(yaml.safe_dump(REGISTRY))

        def enable(config):
            config["agents"] = {
                "enabled": True,
                "max_hops": max_hops,
                "registry_path": "agents.yaml",
                "attr_store_ref": "https://aas.internal",
                **extra,
            }

        return make_tts(enable)

    return build


def denial(tts, event_type):
    return [e for e in tts.sink.events if e.event_type is event_type][-1]


async def test_subject_initiated_agent_issuance_agent_profile_03_s3_5_1(agent_tts):
    """agent-profile-03 §3.2.1, §3.5.1: act.sub resolves the agent; hop_count = 1; act copied."""
    tts = agent_tts()
    subject = tts.access_token(act={"sub": "assistant-agent"})
    claims = tts.verifier().verify(await tts.issue(subject_token=subject)).claims
    ctx = claims.agentic_ctx
    assert ctx is not None
    assert ctx.originator.id == ctx.proximate_agent.id == "assistant-agent"
    assert ctx.chain_metadata.hop_count == 1
    assert ctx.chain_metadata.min_assurance_level == "high"
    assert ctx.attr_store_ref == "https://aas.internal"
    assert dict(claims.act) == {"sub": "assistant-agent"}
    event = tts.sink.of_type(EventType.TOKEN_ISSUED)[0]
    assert event.agent_context is not None
    assert event.agent_context.originator == "assistant-agent"


async def test_client_id_resolves_agent_agent_profile_03_s3_6_1(agent_tts):
    """agent-profile-03 §3.6.1: client_id lookup in the Agent Attribute Store."""
    tts = agent_tts(include_assurance=False)
    claims = tts.verifier().verify(await tts.issue()).claims
    assert claims.agentic_ctx.proximate_agent.id == "assistant-agent"
    assert claims.agentic_ctx.chain_metadata.min_assurance_level is None


async def test_non_agent_gets_no_agentic_ctx_agent_profile_03_s3_6_1(agent_tts):
    """agent-profile-03 §3.6.1 step 4."""
    tts = agent_tts()
    subject = tts.access_token(client_id="not-an-agent")
    claims = tts.verifier().verify(await tts.issue(subject_token=subject)).claims
    assert claims.agentic_ctx is None


async def test_autonomous_agent_without_act_agent_profile_03_s3_2_2(agent_tts):
    """agent-profile-03 §3.2.2: client credentials; originator from client_id; no act."""
    tts = agent_tts()
    subject = tts.access_token(sub="auto-client", client_id="auto-client")
    claims = tts.verifier().verify(await tts.issue(subject_token=subject)).claims
    assert claims.act is None
    assert claims.agentic_ctx.originator.id == "auto-agent"


async def test_client_credentials_with_act_is_denied_agent_profile_03_s3_2_2(agent_tts):
    """agent-profile-03 §3.2.2: such a Txn-Token MUST NOT contain act; PyTraT denies."""
    tts = agent_tts()
    subject = tts.access_token(
        sub="auto-client", client_id="auto-client", act={"sub": "auto-agent"}
    )
    response = await tts.post(tts.form(subject_token=subject))
    assert response.json()["error"] == "invalid_grant"
    assert denial(tts, EventType.ISSUANCE_DENIED).reason_code is ReasonCode.ISSUANCE_NOT_AUTHORIZED


async def test_unregistered_actor_with_other_agent_client_is_denied(agent_tts):
    tts = agent_tts()
    subject = tts.access_token(act={"sub": "ghost-agent"})  # client_id web-app is another agent
    response = await tts.post(tts.form(subject_token=subject))
    assert response.json()["error"] == "invalid_grant"
    assert denial(tts, EventType.ISSUANCE_DENIED).reason_code is ReasonCode.AGENT_UNVERIFIED


async def agent_token(tts):
    subject = tts.access_token(act={"sub": "assistant-agent"})
    return await tts.issue(subject_token=subject, scope="payments.transfer payments.read")


async def test_agent_replacement_agent_profile_03_s3_3_1(agent_tts):
    """agent-profile-03 §3.3.1: proximate updated, hop+1, assurance min, req_wl appended."""
    tts = agent_tts()
    first = tts.verifier().verify(await agent_token(tts)).claims
    response = await tts.post(
        tts.replacement_form(
            tts.components.signer.sign(first.to_payload()),
            workload="billing-agent",
            scope="payments.read",
        )
    )
    assert response.status_code == 200, response.text
    claims = tts.verifier().verify(response.json()["access_token"]).claims
    ctx = claims.agentic_ctx
    assert ctx.originator.id == "assistant-agent"
    assert ctx.proximate_agent.id == "billing-agent"
    assert ctx.chain_metadata.hop_count == 2
    assert ctx.chain_metadata.min_assurance_level == "medium"
    assert claims.req_wl == "api-gateway,billing-agent"
    assert claims.requesting_workloads == ("api-gateway", "billing-agent")
    assert claims.act == first.act
    assert (claims.txn, claims.sub, claims.aud) == (first.txn, first.sub, first.aud)


async def test_non_agent_replacement_carries_ctx_unchanged_agent_profile_03_s3_3_2(agent_tts):
    """agent-profile-03 §3.3.2: agentic_ctx carried forward without modification."""
    tts = agent_tts()
    token = await agent_token(tts)
    before = tts.verifier().verify(token).claims
    response = await tts.post(tts.replacement_form(token, scope="payments.read"))
    after = tts.verifier().verify(response.json()["access_token"]).claims
    assert after.agentic_ctx == before.agentic_ctx
    assert after.req_wl == "api-gateway,payment-service"


async def test_requester_agent_is_never_taken_from_act(agent_tts):
    """agent-profile-03 §4.2.2: the token's act names the original actor, not the requester."""
    tts = agent_tts()
    token = await agent_token(tts)  # act.sub = assistant-agent (high)
    response = await tts.post(tts.replacement_form(token, scope="payments.read"))
    ctx = tts.verifier().verify(response.json()["access_token"]).claims.agentic_ctx
    assert ctx.proximate_agent.id == "assistant-agent"  # unchanged: payment-service is no agent
    assert ctx.chain_metadata.hop_count == 1


async def test_hop_limit_bypass_is_rejected_agent_profile_03_s4_2_3(agent_tts):
    """agent-profile-03 §4.2.3: exceeding the hop threshold MUST be rejected."""
    tts = agent_tts(max_hops=1)
    token = await agent_token(tts)
    response = await tts.post(
        tts.replacement_form(token, workload="billing-agent", scope="payments.read")
    )
    assert response.json()["error"] == "invalid_grant"
    assert (
        denial(tts, EventType.REPLACEMENT_DENIED).reason_code is ReasonCode.AGENT_HOP_LIMIT_EXCEEDED
    )


async def test_agent_replacing_plain_token_requires_chain(agent_tts):
    tts = agent_tts()
    subject = tts.access_token(client_id="not-an-agent")
    token = await tts.issue(subject_token=subject, scope="payments.read")
    response = await tts.post(
        tts.replacement_form(token, workload="billing-agent", scope="payments.read")
    )
    assert response.json()["error"] == "invalid_grant"
    assert denial(tts, EventType.REPLACEMENT_DENIED).reason_code is ReasonCode.AGENT_CONTEXT_MISSING


async def test_profile_disabled_still_carries_ctx_forward(make_tts, agent_tts):
    """With the profile off, an existing agentic_ctx is never altered (agent-profile-03 §3.3.2)."""
    tts_on = agent_tts()
    token = await agent_token(tts_on)
    tts_off = make_tts()
    response = await tts_off.post(tts_off.replacement_form(token, scope="payments.read"))
    after = tts_off.verifier().verify(response.json()["access_token"]).claims
    assert after.agentic_ctx == tts_on.verifier().verify(token).claims.agentic_ctx
