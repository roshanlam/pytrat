"""Resource-side agent-chain requirements (agent-profile-03 §3.5.4, §4.2.2 step 12).

A pure checker with no dependency on ``pytrat.policy``. It reads only verified claims and the
trusted Agent Attribute Store. ``session_id`` is never an input (agent-profile-03 §3.5.1, §5.15):
nothing here reads ``proximate_agent.session_id`` or ``originator.session_id``.
"""

from __future__ import annotations

from dataclasses import dataclass

from pytrat.agents.registry import AgentAttributeStore
from pytrat.core.assurance import AssuranceOrdering
from pytrat.core.claims import AgenticContext, TransactionClaims
from pytrat.core.errors import AuthorizationError, DependencyError, PyTraTError, ReasonCode

__all__ = ["AgentRequirements", "check_agent_requirements"]


@dataclass(frozen=True, slots=True)
class AgentRequirements:
    """What a resource requires of the agent chain behind a request.

    Attributes:
        maximum_hops: Highest acceptable ``hop_count``. Without mandatory replacement,
            ``hop_count`` is only a lower bound on the real chain length (§5.14).
        minimum_assurance: Lowest acceptable ``min_assurance_level``. An absent or unknown level
            never satisfies it.
        require_verified_agent: ``proximate_agent.id`` must be registered in the store.
        allowed_originators: If set, ``originator.id`` must be one of these.
        require_agent_context: The token must carry ``agentic_ctx``.

    PyTraT profile: when ``minimum_assurance``, ``require_verified_agent`` or
    ``allowed_originators`` is set, a token without ``agentic_ctx`` is denied (the claim needed for
    the check is missing). ``maximum_hops`` alone is satisfied by a token with no agents.
    """

    maximum_hops: int | None = None
    minimum_assurance: str | None = None
    require_verified_agent: bool = False
    allowed_originators: frozenset[str] | None = None
    require_agent_context: bool = False

    @property
    def needs_agent_context(self) -> bool:
        """True if these requirements cannot be evaluated without ``agentic_ctx``."""
        return (
            self.require_agent_context
            or self.require_verified_agent
            or self.minimum_assurance is not None
            or self.allowed_originators is not None
        )


def check_agent_requirements(
    claims: TransactionClaims,
    requirements: AgentRequirements,
    ordering: AssuranceOrdering,
    store: AgentAttributeStore | None,
) -> None:
    """Enforce ``requirements`` against verified ``claims``. Returns only if all are met.

    Args:
        claims: Claims of a *verified* Txn-Token.
        requirements: The resource's requirements.
        ordering: The deployment's assurance ordering.
        store: The trusted Agent Attribute Store; needed only for ``require_verified_agent``.

    Raises:
        AuthorizationError: ``AGENT_CONTEXT_MISSING``, ``AGENT_HOP_LIMIT_EXCEEDED``,
            ``AGENT_NOT_ALLOWED``, ``AGENT_ASSURANCE_INSUFFICIENT`` or ``AGENT_UNVERIFIED``.
        DependencyError: ``DEPENDENCY_UNAVAILABLE`` if verification is required and the store is
            absent or cannot answer.
        ConfigurationError: If ``minimum_assurance`` is not part of ``ordering``.
    """
    ctx = claims.agentic_ctx
    if ctx is None:
        if requirements.needs_agent_context:
            raise AuthorizationError(
                ReasonCode.AGENT_CONTEXT_MISSING, "token carries no agentic_ctx"
            )
        return
    _check_hops(ctx, requirements)
    _check_originator(ctx, requirements)
    _check_assurance(ctx, requirements, ordering)
    if requirements.require_verified_agent:
        _check_verified(ctx, store)


def _check_hops(ctx: AgenticContext, requirements: AgentRequirements) -> None:
    # agent-profile-03 §3.5.1: RS SHOULD evaluate hop_count against deployment limits.
    limit = requirements.maximum_hops
    if limit is not None and ctx.chain_metadata.hop_count > limit:
        raise AuthorizationError(
            ReasonCode.AGENT_HOP_LIMIT_EXCEEDED, "agent chain exceeds the maximum hop count"
        )


def _check_originator(ctx: AgenticContext, requirements: AgentRequirements) -> None:
    # agent-profile-03 §3.5.1: RS SHOULD use originator.id for originator-based policies.
    allowed = requirements.allowed_originators
    if allowed is not None and ctx.originator.id not in allowed:
        raise AuthorizationError(
            ReasonCode.AGENT_NOT_ALLOWED, "agent chain originator is not allowed"
        )


def _check_assurance(
    ctx: AgenticContext, requirements: AgentRequirements, ordering: AssuranceOrdering
) -> None:
    required = requirements.minimum_assurance
    if required is None:
        return
    # satisfies() raises AGENT_ASSURANCE_INSUFFICIENT itself for absent or unknown levels.
    if not ordering.satisfies(ctx.chain_metadata.min_assurance_level, required):
        raise AuthorizationError(
            ReasonCode.AGENT_ASSURANCE_INSUFFICIENT,
            "agent chain assurance level is below the required level",
        )


def _check_verified(ctx: AgenticContext, store: AgentAttributeStore | None) -> None:
    if store is None:
        raise DependencyError("agent verification required but no agent store is configured")
    try:
        record = store.get(ctx.proximate_agent.id)
    except PyTraTError:
        raise
    except Exception as exc:
        # Fail closed: a store that cannot answer is never "not registered" and never "allowed".
        raise DependencyError("agent store lookup failed") from exc
    if record is None:
        raise AuthorizationError(ReasonCode.AGENT_UNVERIFIED, "proximate agent is not registered")
