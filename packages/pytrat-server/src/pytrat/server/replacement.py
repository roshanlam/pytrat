"""Replacement Txn-Token planning (txn-tokens-11 §13.15). Pure; no I/O and no signing.

A Txn-Token presented as ``subject_token`` (``subject_token_type`` =
``urn:ietf:params:oauth:token-type:txn_token``, PyTraT profile P4) yields a replacement token.
Replacement only attenuates (CLAUDE.md invariant 5): ``txn``, ``sub``, ``aud``, ``iss``, ``tctx``
and ``act`` are copied from the verified input, never taken from the request; scope only shrinks;
``rctx`` only gains members; lifetime never grows unless the deployment opts in. Agent-chain rules
are delegated to :mod:`pytrat.agents`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING

from pytrat.agents import (
    MAX_HOP_LIMIT,
    AgentLimits,
    AgentReplacementPlan,
    assert_replacement_attenuates,
    plan_agent_replacement,
)
from pytrat.core.claims import TransactionClaims
from pytrat.core.clock import Clock
from pytrat.core.errors import PyTraTError, ReasonCode, TokenError
from pytrat.core.keys import KeyProvider
from pytrat.core.scopes import Scope
from pytrat.core.secret import SecretToken
from pytrat.core.validation import TokenVerifier, VerifiedToken, VerifierSettings
from pytrat.server._shaping import (
    build_claims,
    dropped_key_names,
    filter_context,
    lifetime_seconds,
)
from pytrat.server.agent_profile import AgentProfile
from pytrat.server.errors import OAuthError, OAuthErrorCode, translate
from pytrat.server.forms import TokenRequest
from pytrat.server.issuance_policy import IssuancePolicy, WorkloadIssuanceRule
from pytrat.server.workloads import WorkloadIdentity

if TYPE_CHECKING:
    from pytrat.server.settings import TtsSettings

__all__ = [
    "ReplacementPlan",
    "plan_replacement",
    "txn_token_verifier",
    "verify_txn_token",
]

#: Base-profile limits: no agent requester, hop limit effectively unbounded.
_BASE_LIMITS = AgentLimits(max_hops=MAX_HOP_LIMIT)


@dataclass(frozen=True, slots=True)
class ReplacementPlan:
    """The outcome of replacement planning.

    Attributes:
        claims: The claims to sign.
        dropped_keys: Audit-safe names of request members that were not copied.
        extends_lifetime: True if ``exp`` is later than the input token's ``exp``.
        requester_is_agent: True if the requester is a registered agent.
    """

    claims: TransactionClaims
    dropped_keys: tuple[str, ...]
    extends_lifetime: bool
    requester_is_agent: bool


def txn_token_verifier(settings: TtsSettings, keys: KeyProvider, clock: Clock) -> TokenVerifier:
    """Build the verifier for input Txn-Tokens: this Trust Domain, this issuer, this TTS's keys."""
    return TokenVerifier(
        VerifierSettings(
            trust_domain=settings.trust_domain,
            algorithms=frozenset(settings.algorithms),
            expected_issuer=settings.issuer,
            max_lifetime=timedelta(seconds=settings.token_lifetime_seconds),
            leeway=timedelta(seconds=settings.leeway_seconds),
        ),
        keys,
        clock,
    )


def verify_txn_token(verifier: TokenVerifier, subject_token: SecretToken) -> VerifiedToken:
    """Verify a Txn-Token presented for replacement.

    Raises:
        OAuthError: ``invalid_grant`` with the verifier's reason code.
    """
    try:
        return verifier.verify(subject_token.reveal())
    except TokenError as exc:
        raise OAuthError(
            OAuthErrorCode.INVALID_GRANT, f"subject Txn-Token rejected: {exc.detail}", exc.reason
        ) from None


def _check_requester(policy: IssuancePolicy, workload: WorkloadIdentity) -> WorkloadIssuanceRule:
    rule = policy.rule_for(workload.id)
    if not rule.may_replace:
        raise OAuthError(
            OAuthErrorCode.UNAUTHORIZED_CLIENT,
            "workload is not authorized to replace Txn-Tokens",
            ReasonCode.ISSUANCE_NOT_AUTHORIZED,
        )
    return rule


def _scope(requested: Scope, current: Scope, rule: WorkloadIssuanceRule) -> Scope:
    # txn-tokens-11 §13.15: MUST NOT enable modifications that expand the scope of permitted
    # actions. A widening request is refused, not silently narrowed.
    if not requested.issubset(current):
        raise OAuthError(
            OAuthErrorCode.INVALID_SCOPE,
            "requested scope exceeds the subject Txn-Token's scope",
            ReasonCode.REPLACEMENT_WIDENS_AUTHORIZATION,
        )
    granted = requested.intersection(rule.scope)
    if granted is None:
        raise OAuthError(
            OAuthErrorCode.INVALID_SCOPE,
            "no requested scope is permitted",
            ReasonCode.SCOPE_INSUFFICIENT,
        )
    return granted


def _expiry(
    now: int,
    current: TransactionClaims,
    rule: WorkloadIssuanceRule,
    settings: TtsSettings,
    replacement_count: int,
) -> int:
    expires_at = now + lifetime_seconds(settings.token_lifetime_seconds, rule.max_lifetime_seconds)
    if not settings.replacement.extend_lifetime:
        # PyTraT profile: by default a replacement never outlives its input.
        return min(expires_at, current.exp)
    # txn-tokens-11 §13.15: a TTS that extends lifetimes SHOULD limit the number of replacements.
    if (
        expires_at > current.exp
        and replacement_count >= settings.replacement.max_replacements_per_txn
    ):
        raise OAuthError(
            OAuthErrorCode.INVALID_GRANT,
            "replacement limit for this transaction reached",
            ReasonCode.REPLACEMENT_LIMIT_EXCEEDED,
        )
    return expires_at


def _rctx(
    current: Mapping[str, object] | None,
    request: TokenRequest,
    rule: WorkloadIssuanceRule,
) -> tuple[dict[str, object], tuple[str, ...]]:
    # txn-tokens-11 §13.15: MAY enable additional asserted values. Existing rctx members are kept
    # verbatim; allowlisted request_context members may only be *added*, never overwrite.
    rctx: dict[str, object] = dict(current or {})
    allowed, dropped = filter_context(request.request_context, rule.rctx, label="request_context")
    conflicting = tuple(key for key in allowed if key in rctx)
    rctx.update({key: value for key, value in allowed.items() if key not in rctx})
    return rctx, dropped + conflicting


def _agent_plan(
    current: TransactionClaims,
    workload: WorkloadIdentity,
    scope: Scope,
    agents: AgentProfile | None,
) -> tuple[AgentReplacementPlan, AgentLimits]:
    limits = agents.limits if agents is not None else _BASE_LIMITS
    try:
        # agent-profile-03 §4.2.2 step 8: identify the requester from its authenticated workload
        # identity, never from the subject token's act.
        requester = agents.requester_record(workload) if agents is not None else None
        # agent-profile-03 §3.3: immutables copied, req_wl appended, agentic_ctx advanced (or
        # carried forward unchanged for a non-agent requester, §3.3.2).
        plan = plan_agent_replacement(current, requester, workload.id, scope, limits)
    except PyTraTError as exc:
        raise translate(exc, OAuthErrorCode.INVALID_GRANT) from None
    return plan, limits


def plan_replacement(  # noqa: PLR0917 - stage signature shared with the pipeline
    current: VerifiedToken,
    request: TokenRequest,
    workload: WorkloadIdentity,
    policy: IssuancePolicy,
    settings: TtsSettings,
    clock: Clock,
    replacement_count: int,
    *,
    agents: AgentProfile | None = None,
) -> ReplacementPlan:
    """Plan a replacement for a verified Txn-Token.

    Args:
        current: The verified input Txn-Token (see :func:`verify_txn_token`).
        request: The parsed request.
        workload: The authenticated requesting workload.
        policy: The issuance policy (the workload needs ``may_replace``).
        settings: TTS settings.
        clock: Time source.
        replacement_count: Replacements already recorded for ``current.claims.txn``.
        agents: The agent profile, or ``None`` when disabled.

    Returns:
        The claims to sign.

    Raises:
        OAuthError: ``unauthorized_client`` if the workload may not replace; ``invalid_grant`` for
            an expired input, an exceeded replacement or hop limit, or an agent-profile violation;
            ``invalid_target`` for a different audience; ``invalid_scope`` for a widening or
            empty scope; ``invalid_request`` for a mistyped context member.
    """
    rule = _check_requester(policy, workload)
    claims = current.claims
    now = int(clock.now())
    # txn-tokens-11 §13.15: MUST NOT issue when the token being replaced has expired. No leeway.
    if now >= claims.exp:
        raise OAuthError(
            OAuthErrorCode.INVALID_GRANT, "subject Txn-Token has expired", ReasonCode.TOKEN_EXPIRED
        )
    # txn-tokens-11 §13.15: aud MUST NOT change.
    if request.audience != claims.aud:
        raise OAuthError(
            OAuthErrorCode.INVALID_TARGET,
            "audience differs from the subject Txn-Token",
            ReasonCode.TRUST_DOMAIN_MISMATCH,
        )
    scope = _scope(request.scope, claims.scope, rule)
    agent_plan, limits = _agent_plan(claims, workload, scope, agents)
    expires_at = _expiry(now, claims, rule, settings, replacement_count)
    rctx, dropped_rctx = _rctx(claims.rctx, request, rule)
    # tctx is immutable through the call chain (txn-tokens-11 §9.2.3): request_details are ignored.
    dropped_tctx = tuple(request.request_details or ())

    payload: dict[str, object] = {**agent_plan.to_claims(), "iat": now, "exp": expires_at}
    if claims.iss is not None:
        payload["iss"] = claims.iss
    if claims.tctx is not None:
        payload["tctx"] = claims.tctx
    if rctx:
        payload["rctx"] = rctx
    new_claims = build_claims(payload, request.subject_token)
    try:
        # Defence in depth: the token about to be signed must only attenuate its input.
        assert_replacement_attenuates(claims, new_claims, limits)
    except PyTraTError as exc:
        raise translate(exc, OAuthErrorCode.INVALID_GRANT) from None
    return ReplacementPlan(
        claims=new_claims,
        dropped_keys=dropped_key_names(dropped_tctx, dropped_rctx),
        extends_lifetime=expires_at > claims.exp,
        requester_is_agent=agent_plan.requester_is_agent,
    )
