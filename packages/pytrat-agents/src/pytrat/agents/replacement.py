"""Pure agent-chain computation for issuance and replacement (agent-profile-03 §3.3, §4.2).

The reference TTS (``pytrat.server``) calls these functions; they do no I/O and sign nothing,
because only the TTS signs. The server identifies the requesting workload, looks up its agent
record and mints the token from an :class:`AgentReplacementPlan`.

Every function here only attenuates: ``txn``, ``sub``, ``aud``, ``act`` and ``originator`` never
change, scope only shrinks, ``min_assurance_level`` only falls and ``hop_count`` only rises.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from pytrat.agents.registry import AgentRecord
from pytrat.core.assurance import DEFAULT_LEVELS, AssuranceOrdering
from pytrat.core.claims import (
    AgenticContext,
    AgentIdentity,
    ChainMetadata,
    JsonObject,
    TransactionClaims,
)
from pytrat.core.errors import AuthorizationError, ConfigurationError, ReasonCode
from pytrat.core.scopes import Scope

__all__ = [
    "MAX_HOP_LIMIT",
    "AgentLimits",
    "AgentReplacementPlan",
    "append_workload",
    "assert_replacement_attenuates",
    "initial_agentic_ctx",
    "next_agentic_ctx",
    "plan_agent_replacement",
    "strip_for_egress",
]

#: Upper bound accepted for ``max_hops``; matches the core ``hop_count`` claim bound.
MAX_HOP_LIMIT = 10_000

_WORKLOAD_SEPARATOR = ","


@dataclass(frozen=True, slots=True)
class AgentLimits:
    """Deployment limits for agent chains, fixed at TTS startup.

    Attributes:
        max_hops: Highest ``hop_count`` a token may carry (agent-profile-03 §4.2.3, §5.12).
        ordering: The deployment's ordered assurance levels (§3.5.1).
        default_assurance: Level assumed for chain members whose level was never recorded, i.e.
            when a token has ``agentic_ctx`` but no ``min_assurance_level`` (PyTraT profile P6).
            Defaults to the lowest level. Setting anything higher is an explicit trust decision:
            it lets an agent hop *add* a level the original token never proved.
        require_replacement: The deployment enforces chain integrity (§3.3, §5.14), so every
            agent hop must already be recorded. When True (default), an agent replacing a token
            that carries no ``agentic_ctx`` is denied with ``AGENT_CONTEXT_MISSING``. When False,
            such a request starts a new chain whose originator is the requesting agent
            (PyTraT profile).

    Raises:
        ConfigurationError: If ``max_hops`` is outside ``1..MAX_HOP_LIMIT`` or
            ``default_assurance`` is not part of ``ordering``.
    """

    max_hops: int
    ordering: AssuranceOrdering = field(default_factory=AssuranceOrdering)
    default_assurance: str = DEFAULT_LEVELS[0]
    require_replacement: bool = True

    def __post_init__(self) -> None:
        if isinstance(self.max_hops, bool) or not 1 <= self.max_hops <= MAX_HOP_LIMIT:
            raise ConfigurationError(f"max_hops must be between 1 and {MAX_HOP_LIMIT}")
        self.ordering.require_known(self.default_assurance)


@dataclass(frozen=True, slots=True)
class AgentReplacementPlan:
    """The claims a replacement Txn-Token must carry, computed from the subject token.

    The immutable claims are copied from the subject token here, so the server mints from one
    value and cannot accidentally take them from the request (agent-profile-03 §3.3.1, §4.2.1;
    txn-tokens-11 §13.15). ``tctx``, ``rctx``, ``iss``, ``iat`` and ``exp`` remain the server's
    responsibility.

    Attributes:
        txn: Copied unchanged.
        sub: Copied unchanged.
        aud: Copied unchanged.
        act: Copied unchanged (§3.3.1: "The act claim is immutable").
        scope: The attenuated scope.
        req_wl: The updated requesting-workload chain.
        agentic_ctx: The new agent context, or ``None`` when neither the subject token nor the
            requester involves an agent.
        requester_is_agent: True if the requester was identified as an agent (§3.6).
    """

    txn: str
    sub: str
    aud: str
    act: JsonObject | None
    scope: Scope
    req_wl: str
    agentic_ctx: AgenticContext | None
    requester_is_agent: bool

    def to_claims(self) -> dict[str, object]:
        """Return the planned claims as a JSON-compatible fragment, omitting absent values."""
        claims: dict[str, object] = {
            "txn": self.txn,
            "sub": self.sub,
            "aud": self.aud,
            "scope": str(self.scope),
            "req_wl": self.req_wl,
        }
        if self.act is not None:
            claims["act"] = _thaw(self.act)
        if self.agentic_ctx is not None:
            claims["agentic_ctx"] = self.agentic_ctx.model_dump(mode="json", exclude_none=True)
        return claims


def initial_agentic_ctx(
    agent: AgentRecord,
    *,
    session_id: str | None = None,
    ordering: AssuranceOrdering,
    include_assurance: bool,
    attr_store_ref: str | None = None,
) -> AgenticContext:
    """Build ``agentic_ctx`` for initial issuance to an identified agent.

    agent-profile-03 §3.5.1: ``hop_count`` is "Set to 1 at initial issuance" and, for a single
    agent, ``originator.id`` and ``proximate_agent.id`` "have the same value".

    Args:
        agent: The agent resolved from the store (see :func:`pytrat.agents.resolve_agent`).
        session_id: Session hint from the agent's infrastructure. Informational only (§3.5.1);
            recorded on both originator and proximate agent, never used for authorization.
        ordering: The deployment's assurance ordering.
        include_assurance: Record ``min_assurance_level`` from the agent's stored level (§3.5).
        attr_store_ref: Optional Agent Attribute Store URI (§3.5.1, informational).
    """
    identity = AgentIdentity(id=agent.id, session_id=session_id)
    level = ordering.minimum(agent.assurance_level, agent.assurance_level)
    return AgenticContext(
        originator=identity,
        proximate_agent=identity,
        chain_metadata=ChainMetadata(
            hop_count=1, min_assurance_level=level if include_assurance else None
        ),
        attr_store_ref=attr_store_ref,
    )


def next_agentic_ctx(
    current: AgenticContext | None,
    requester: AgentRecord | None,
    limits: AgentLimits,
    *,
    session_id: str | None = None,
) -> AgenticContext | None:
    """Compute ``agentic_ctx`` for a replacement requested by ``requester``.

    - Non-agent requester (``requester is None``): ``current`` is returned unchanged
      (agent-profile-03 §3.3.2: "MUST be carried forward without modification").
    - Agent requester: ``proximate_agent`` becomes the requester with ``session_id``
      (§3.3.1), ``hop_count`` rises by one (§3.3.1), ``min_assurance_level`` becomes
      ``min(existing or default_assurance, requester level)`` (§3.3.1, §4.2, §5.9; PyTraT
      profile P6), and ``originator`` and ``attr_store_ref`` are kept (§4.2.1).

    Args:
        current: ``agentic_ctx`` of the verified subject token.
        requester: Store record of the *authenticated* requesting workload, or ``None`` if it is
            not a registered agent. Never derived from the subject token's ``act``.
        limits: Deployment limits.
        session_id: The requesting agent's session hint (informational, §3.5.1). Replaces the
            previous proximate agent's value; ``None`` clears it.

    Returns:
        The new context, or ``None`` if there is none to carry.

    Raises:
        AuthorizationError: ``AGENT_HOP_LIMIT_EXCEEDED`` if the resulting ``hop_count`` exceeds
            ``limits.max_hops`` (§4.2.3: the request "MUST be rejected");
            ``AGENT_CONTEXT_MISSING`` if an agent replaces a token without ``agentic_ctx`` and
            ``limits.require_replacement`` is set.
    """
    if requester is None:
        if current is not None:
            _check_hops(current.chain_metadata.hop_count, limits)
        return current
    if current is None:
        return _start_chain(requester, limits, session_id)
    hop_count = current.chain_metadata.hop_count + 1
    _check_hops(hop_count, limits)
    existing = current.chain_metadata.min_assurance_level or limits.default_assurance
    return AgenticContext(
        # agent-profile-03 §4.2.1: "The originator object MUST NOT be modified."
        originator=current.originator,
        proximate_agent=AgentIdentity(id=requester.id, session_id=session_id),
        chain_metadata=ChainMetadata(
            hop_count=hop_count,
            # agent-profile-03 §5.9: never higher than the incoming value.
            min_assurance_level=limits.ordering.minimum(existing, requester.assurance_level),
        ),
        attr_store_ref=current.attr_store_ref,
    )


def append_workload(req_wl: str, workload: str) -> str:
    """Append ``workload`` to the ``req_wl`` chain.

    agent-profile-03 §3.3.1: ``req_wl`` "MUST be updated by appending the current requesting
    workload's identifier, using the comma (,) character as separator". PyTraT profile P5:
    identifiers containing a comma would make the chain ambiguous and are rejected.

    Raises:
        AuthorizationError: ``ISSUANCE_NOT_AUTHORIZED`` if ``workload`` is empty or contains a
            comma.
    """
    _check_workload(workload)
    return f"{req_wl}{_WORKLOAD_SEPARATOR}{workload}"


def plan_agent_replacement(
    current: TransactionClaims,
    requester_agent: AgentRecord | None,
    requester_workload: str,
    requested_scope: Scope | None,
    limits: AgentLimits,
    *,
    session_id: str | None = None,
) -> AgentReplacementPlan:
    """Plan a replacement Txn-Token under the agent profile.

    Args:
        current: Claims of the *verified*, unexpired subject Txn-Token.
        requester_agent: Store record of the authenticated requesting workload, or ``None`` if it
            is not a registered agent (§3.6.1). Never derived from ``current.act``.
        requester_workload: Identifier of the authenticated requesting workload, for ``req_wl``.
        requested_scope: Scope asked for, or ``None`` to keep the current scope.
        limits: Deployment limits.
        session_id: The requesting agent's session hint (informational only).

    Returns:
        The plan. ``req_wl`` is comma-appended when the result carries ``agentic_ctx`` (§3.3.1,
        P5); otherwise base rules apply and it names the requesting workload (txn-tokens-11
        §9.2).

    Raises:
        AuthorizationError: ``REPLACEMENT_WIDENS_AUTHORIZATION`` if ``requested_scope`` is not a
            subset of the current scope (txn-tokens-11 §13.15; agent-profile-03 §3.3.1, §5.5);
            ``ISSUANCE_NOT_AUTHORIZED`` for an invalid workload identifier; and anything
            :func:`next_agentic_ctx` raises.
    """
    scope = current.scope
    if requested_scope is not None:
        if not requested_scope.issubset(current.scope):
            raise AuthorizationError(
                ReasonCode.REPLACEMENT_WIDENS_AUTHORIZATION,
                "requested scope is not a subset of the subject token's scope",
            )
        scope = requested_scope
    agentic_ctx = next_agentic_ctx(
        current.agentic_ctx, requester_agent, limits, session_id=session_id
    )
    if agentic_ctx is None:
        _check_workload(requester_workload)
        req_wl = requester_workload
    else:
        req_wl = append_workload(current.req_wl, requester_workload)
    return AgentReplacementPlan(
        txn=current.txn,
        sub=current.sub,
        aud=current.aud,
        act=current.act,
        scope=scope,
        req_wl=req_wl,
        agentic_ctx=agentic_ctx,
        requester_is_agent=requester_agent is not None,
    )


def assert_replacement_attenuates(
    current: TransactionClaims, replacement: TransactionClaims, limits: AgentLimits
) -> None:
    """Check that ``replacement`` only attenuates ``current``.

    Defence in depth for the server to run on the token it is about to sign; also the oracle
    for property tests.

    Raises:
        AuthorizationError: ``REPLACEMENT_WIDENS_AUTHORIZATION`` naming the first violated rule.
    """
    _require(
        (current.txn, current.sub, current.aud)
        == (replacement.txn, replacement.sub, replacement.aud),
        "txn, sub and aud must not change",  # txn-tokens-11 §13.15
    )
    _require(current.act == replacement.act, "act must not change")  # agent-profile-03 §3.3.1
    _require(replacement.scope.issubset(current.scope), "scope must not widen")
    before, after = current.agentic_ctx, replacement.agentic_ctx
    if before is None:
        return
    _require(after is not None, "agentic_ctx must not be dropped")
    assert after is not None  # noqa: S101 - narrowing for mypy after _require
    # agent-profile-03 §4.2.1: originator preservation.
    _require(after.originator == before.originator, "originator must not change")
    _require(
        after.chain_metadata.hop_count >= before.chain_metadata.hop_count,
        "hop_count must not decrease",
    )
    # agent-profile-03 §5.9: never a higher min_assurance_level than the incoming token.
    ordering = limits.ordering
    before_level = before.chain_metadata.min_assurance_level or limits.default_assurance
    after_level = after.chain_metadata.min_assurance_level or limits.default_assurance
    _require(
        ordering.rank(after_level) <= ordering.rank(before_level),
        "min_assurance_level must not rise",
    )


def strip_for_egress(ctx: AgenticContext | None) -> AgenticContext | None:
    """Remove internal references before a token leaves the Trust Domain.

    agent-profile-03 §5.13: on egress "the TTS MUST strip the attr_store_ref field and any other
    internal identifiers". PyTraT strips ``attr_store_ref``; unknown members are already dropped
    when claims are parsed. Which other identifiers are internal is deployment-specific.
    """
    if ctx is None or ctx.attr_store_ref is None:
        return ctx
    return AgenticContext(
        originator=ctx.originator,
        proximate_agent=ctx.proximate_agent,
        chain_metadata=ctx.chain_metadata,
    )


def _start_chain(
    requester: AgentRecord, limits: AgentLimits, session_id: str | None
) -> AgenticContext:
    if limits.require_replacement:
        raise AuthorizationError(
            ReasonCode.AGENT_CONTEXT_MISSING,
            "agent requested replacement of a token without agentic_ctx",
        )
    # PyTraT profile: a new chain at the first agent hop. The level is capped by
    # default_assurance because the earlier, non-agent part of the chain was never assessed.
    identity = AgentIdentity(id=requester.id, session_id=session_id)
    return AgenticContext(
        originator=identity,
        proximate_agent=identity,
        chain_metadata=ChainMetadata(
            hop_count=1,
            min_assurance_level=limits.ordering.minimum(
                limits.default_assurance, requester.assurance_level
            ),
        ),
    )


def _check_hops(hop_count: int, limits: AgentLimits) -> None:
    # agent-profile-03 §4.2.3, §5.12: exceeding the threshold MUST reject the replacement.
    if hop_count > limits.max_hops:
        raise AuthorizationError(
            ReasonCode.AGENT_HOP_LIMIT_EXCEEDED, "agent chain exceeds the maximum hop count"
        )


def _check_workload(workload: str) -> None:
    if not workload or _WORKLOAD_SEPARATOR in workload:
        raise AuthorizationError(
            ReasonCode.ISSUANCE_NOT_AUTHORIZED,
            "workload identifier must be non-empty and must not contain ','",
        )


def _require(condition: bool, detail: str) -> None:
    if not condition:
        raise AuthorizationError(ReasonCode.REPLACEMENT_WIDENS_AUTHORIZATION, detail)


def _thaw(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_thaw(item) for item in value]
    return value
