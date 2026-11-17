"""Agent identification at initial issuance (agent-profile-03 §3.2, §3.5.1, §3.6.1).

These functions are for the TTS at *initial issuance*, where the access token's ``act`` and
``client_id`` describe the caller. At *replacement*, the requesting agent is the authenticated
workload calling the TTS (§4.2.2 step 8); the ``act`` claim inside the subject Txn-Token names the
original actor and MUST NOT be used to identify the replacement requester.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum

from pytrat.agents.registry import AgentAttributeStore, AgentRecord
from pytrat.core.errors import AuthorizationError, ReasonCode, TokenError

__all__ = ["AgentMode", "agent_mode", "resolve_agent"]


class AgentMode(StrEnum):
    """How an agent transaction was started (agent-profile-03 §3.2)."""

    SUBJECT_INITIATED = "subject_initiated"
    """A human subject delegated to the agent; the access token carries ``act`` (§3.2.1)."""
    AUTONOMOUS = "autonomous"
    """Client Credentials Grant; no delegation and no ``act`` (§3.2.2)."""


def agent_mode(*, act: Mapping[str, object] | None, client_credentials: bool) -> AgentMode:
    """Classify an issuance request and enforce the autonomous-flow rule.

    Args:
        act: The ``act`` claim of the validated access token, if any.
        client_credentials: True if the access token was issued by a Client Credentials Grant.

    Returns:
        :attr:`AgentMode.AUTONOMOUS` for client credentials, otherwise
        :attr:`AgentMode.SUBJECT_INITIATED`.

    Raises:
        AuthorizationError: ``ISSUANCE_NOT_AUTHORIZED`` if a client-credentials token carries
            ``act``. agent-profile-03 §3.2.2: such a Txn-Token "MUST NOT contain an act claim";
            PyTraT profile: deny rather than silently drop the claim.
    """
    if client_credentials:
        if act is not None:
            raise AuthorizationError(
                ReasonCode.ISSUANCE_NOT_AUTHORIZED,
                "client-credentials (autonomous) access token must not carry 'act'",
            )
        return AgentMode.AUTONOMOUS
    return AgentMode.SUBJECT_INITIATED


def resolve_agent(
    store: AgentAttributeStore,
    *,
    act: Mapping[str, object] | None,
    client_id: str | None,
) -> AgentRecord | None:
    """Identify the agent behind an issuance request.

    agent-profile-03 §3.5.1: the agent identifier is derived "via act.sub, Agent Attribute Store
    lookup, or client_id — in that priority order". ``act.sub`` is looked up as an agent id, then
    ``client_id`` as an OAuth client id (§3.6.1).

    Args:
        store: The trusted Agent Attribute Store.
        act: The ``act`` claim of the *validated* access token, if any.
        client_id: The ``client_id`` of the *validated* access token, if any.

    Returns:
        The registered agent, or ``None`` if the caller is not a registered agent. Per §3.6.1
        step 4, ``None`` means the TTS MUST NOT populate ``agentic_ctx``.

    Raises:
        TokenError: ``CLAIM_INVALID`` if ``act`` is present without a non-empty string ``sub``.
        AuthorizationError: ``AGENT_UNVERIFIED`` if ``act.sub`` names an unregistered agent while
            ``client_id`` resolves to a *different* registered agent (PyTraT profile: falling back
            would attribute the chain to an agent other than the actual actor).
        DependencyError: ``DEPENDENCY_UNAVAILABLE`` if the store cannot answer.
    """
    actor_id = _actor_id(act)
    if actor_id is not None:
        record = store.get(actor_id)
        if record is not None:
            return record
    if client_id is None:
        return None
    record = store.by_client_id(client_id)
    if record is not None and actor_id is not None and record.id != actor_id:
        raise AuthorizationError(
            ReasonCode.AGENT_UNVERIFIED,
            "act.sub is not a registered agent and does not match the client's agent",
        )
    return record


def _actor_id(act: Mapping[str, object] | None) -> str | None:
    if act is None:
        return None
    actor = act.get("sub")
    if not isinstance(actor, str) or not actor:
        raise TokenError(ReasonCode.CLAIM_INVALID, "claim 'act.sub' is invalid")
    return actor
