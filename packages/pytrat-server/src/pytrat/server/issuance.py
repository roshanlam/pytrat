"""Initial Txn-Token issuance planning (txn-tokens-11 §11.3). Pure; no I/O and no signing.

:func:`plan_issuance` turns an authenticated request, a validated subject and the issuance policy
into the exact claims to sign, or raises an :class:`~pytrat.server.errors.OAuthError`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pytrat.agents import agent_mode, initial_agentic_ctx, resolve_agent
from pytrat.core.claims import AgenticContext, TransactionClaims
from pytrat.core.clock import Clock
from pytrat.core.errors import PyTraTError, ReasonCode
from pytrat.core.scopes import Scope
from pytrat.server._shaping import (
    build_claims,
    dropped_key_names,
    filter_context,
    lifetime_seconds,
)
from pytrat.server.agent_profile import AgentProfile
from pytrat.server.errors import OAuthError, OAuthErrorCode, translate
from pytrat.server.forms import TokenRequest
from pytrat.server.issuance_policy import (
    IssuancePolicy,
    JsonType,
    WorkloadIssuanceRule,
    value_matches,
)
from pytrat.server.subjects import SubjectInfo
from pytrat.server.workloads import WorkloadIdentity

if TYPE_CHECKING:
    from pytrat.server.settings import TtsSettings

__all__ = [
    "IssuancePlan",
    "IssuancePolicy",
    "JsonType",
    "WorkloadIssuanceRule",
    "check_audience",
    "plan_issuance",
    "value_matches",
]


@dataclass(frozen=True, slots=True)
class IssuancePlan:
    """The outcome of issuance planning.

    Attributes:
        claims: The claims to sign.
        dropped_keys: Names of ``request_details`` / ``request_context`` members that were not
            allowlisted and were dropped, prefixed ``tctx.`` / ``rctx.``. Names only, made safe
            for audit (anything but a short identifier is replaced by a digest).
    """

    claims: TransactionClaims
    dropped_keys: tuple[str, ...]


def check_audience(
    audience: str, rule: WorkloadIssuanceRule, workload: WorkloadIdentity, settings: TtsSettings
) -> None:
    """Check the requested audience.

    txn-tokens-11 §11.1: audience "MUST be set to the Trust Domain name".

    Raises:
        OAuthError: ``invalid_target`` if the audience is not the Trust Domain or is not allowed
            for this workload.
    """
    allowed = {settings.trust_domain}
    if rule.audiences:
        allowed &= set(rule.audiences)
    registered = settings.workload(workload.id)
    if registered is not None and registered.allowed_audiences is not None:
        allowed &= set(registered.allowed_audiences)
    if audience not in allowed:
        raise OAuthError(
            OAuthErrorCode.INVALID_TARGET,
            "audience is not this Trust Domain",
            ReasonCode.TRUST_DOMAIN_MISMATCH,
        )


def _granted_scope(requested: Scope, rule: WorkloadIssuanceRule, subject: SubjectInfo) -> Scope:
    # txn-tokens-11 §13.14: an unknown subject scope MUST NOT be treated as unconstrained.
    if subject.scope is None:
        raise OAuthError(
            OAuthErrorCode.INVALID_SCOPE,
            "the subject token's scope cannot be determined",
            ReasonCode.SCOPE_INSUFFICIENT,
        )
    # txn-tokens-11 §13.6: the Txn-Token scope MUST be equal to or less than the subject's.
    # PyTraT profile: granted = requested ∩ workload policy ∩ subject scope.
    within_policy = requested.intersection(rule.scope)
    granted = within_policy.intersection(subject.scope) if within_policy else None
    if granted is None:
        raise OAuthError(
            OAuthErrorCode.INVALID_SCOPE,
            "no requested scope is permitted",
            ReasonCode.SCOPE_INSUFFICIENT,
        )
    return granted


def _expiry(
    now: int,
    rule: WorkloadIssuanceRule,
    subject: SubjectInfo,
    policy: IssuancePolicy,
    lifetime: int,
) -> int:
    expires_at = now + lifetime_seconds(lifetime, rule.max_lifetime_seconds)
    # txn-tokens-11 §6: the Txn-Token MAY outlive the subject token "subject to the policy of the
    # TTS". PyTraT profile: capped at the subject's exp unless the policy opts out.
    if policy.cap_lifetime_at_subject_exp and subject.exp is not None:
        expires_at = min(expires_at, subject.exp)
    if expires_at <= now:
        raise OAuthError(
            OAuthErrorCode.INVALID_GRANT, "subject token has expired", ReasonCode.TOKEN_EXPIRED
        )
    return expires_at


def _agentic_ctx(subject: SubjectInfo, agents: AgentProfile | None) -> AgenticContext | None:
    if agents is None:
        return None
    try:
        # agent-profile-03 §3.2.2: a client-credentials (autonomous) token MUST NOT carry act.
        agent_mode(act=subject.act, client_credentials=subject.client_credentials)
        # agent-profile-03 §3.5.1, §3.6.1: act.sub, then client_id, against the trusted store.
        agent = resolve_agent(agents.store, act=subject.act, client_id=subject.client_id)
    except PyTraTError as exc:
        raise translate(exc, OAuthErrorCode.INVALID_GRANT) from None
    if agent is None:
        # agent-profile-03 §3.6.1 step 4: a non-agent caller gets no agentic_ctx.
        return None
    # agent-profile-03 §3.5.1: hop_count = 1, originator = proximate = the agent.
    return initial_agentic_ctx(
        agent,
        ordering=agents.limits.ordering,
        include_assurance=agents.include_assurance,
        attr_store_ref=agents.attr_store_ref,
    )


def plan_issuance(  # noqa: PLR0917 - stage signature shared with the pipeline
    request: TokenRequest,
    workload: WorkloadIdentity,
    subject: SubjectInfo,
    policy: IssuancePolicy,
    settings: TtsSettings,
    clock: Clock,
    txn_id: str,
    *,
    agents: AgentProfile | None = None,
) -> IssuancePlan:
    """Plan the claims of a new Txn-Token.

    Args:
        request: The parsed request.
        workload: The authenticated requesting workload.
        subject: The validated subject.
        policy: The issuance policy.
        settings: TTS settings (Trust Domain, issuer, lifetime).
        clock: Time source.
        txn_id: The new transaction identifier.
        agents: The agent profile, or ``None`` when disabled.

    Returns:
        The claims to sign and the names of dropped context members.

    Raises:
        OAuthError: ``unauthorized_client`` if the workload has no issuance rule,
            ``invalid_target`` for a wrong audience, ``invalid_scope`` if no scope can be granted
            or the subject's scope is unknown, ``invalid_request`` for a mistyped allowlisted
            context member or an embedded subject token, ``invalid_grant`` for an expired subject
            or an agent-profile violation.
    """
    rule = policy.rule_for(workload.id)
    check_audience(request.audience, rule, workload, settings)
    scope = _granted_scope(request.scope, rule, subject)
    now = int(clock.now())
    expires_at = _expiry(now, rule, subject, policy, settings.token_lifetime_seconds)

    # txn-tokens-11 §11.3: the TTS is authoritative for tctx and rctx; only allowlisted members
    # with the declared JSON type are copied, everything else is dropped and recorded.
    tctx, dropped_tctx = filter_context(request.request_details, rule.tctx, label="request_details")
    rctx, dropped_rctx = filter_context(request.request_context, rule.rctx, label="request_context")
    if subject.authn:
        # txn-tokens-11 §9.2.2: rctx may carry values "independently asserted by the TTS".
        rctx["authn"] = dict(subject.authn)

    payload: dict[str, object] = {
        # txn-tokens-11 §11.3: iat = time of issuance, aud = Trust Domain, unique txn.
        "iss": settings.issuer,
        "aud": settings.trust_domain,
        "iat": now,
        "exp": expires_at,
        "txn": txn_id,
        # txn-tokens-11 §11.2.1, §11.2.2: the TTS determines sub from the validated subject.
        "sub": subject.sub,
        "scope": str(scope),
        # txn-tokens-11 §9.2: req_wl identifies the workload that requested the token.
        "req_wl": workload.id,
    }
    if tctx:
        payload["tctx"] = tctx
    if rctx:
        payload["rctx"] = rctx
    if subject.act is not None:
        # agent-profile-03 §3.2.1 step 7: act is copied as-is.
        payload["act"] = subject.act
    agentic_ctx = _agentic_ctx(subject, agents)
    if agentic_ctx is not None:
        payload["agentic_ctx"] = agentic_ctx.model_dump(mode="json", exclude_none=True)
    # txn-tokens-11 §13.4: build_claims refuses claims that embed the subject token.
    claims = build_claims(payload, request.subject_token)
    return IssuancePlan(claims=claims, dropped_keys=dropped_key_names(dropped_tctx, dropped_rctx))
