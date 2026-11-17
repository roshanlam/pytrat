"""Framework-agnostic enforcement: the one pipeline every integration runs per request.

:class:`TransactionEnforcer` turns transport facts plus parsed request data into either a
:class:`Transaction` (allowed) or a :class:`~pytrat.core.errors.PyTraTError` (denied), emitting
exactly one audit event either way. FastAPI and Django adapt their request objects to it, so both
integrations behave identically.

Pipeline (first failure wins):

1. read exactly one ``Txn-Token`` header (txn-tokens-11 §12.1)
2. verify the token (signature, Trust Domain, lifetime; §12.2)
3. authenticate the calling workload, independently of the token (§13.12)
4. evaluate the route policy: scope, caller, ``tctx`` binding, agent constraints, replay
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass

from pytrat.core import (
    AuditEvent,
    AuditSink,
    BindingResult,
    EventType,
    InboundRequest,
    JsonObject,
    NullSink,
    PyTraTError,
    ReasonCode,
    Scope,
    TokenError,
    TokenVerifier,
    TransactionClaims,
    VerifiedToken,
    WorkloadAuthenticator,
    WorkloadIdentity,
)
from pytrat.core.constants import TXN_TOKEN_HEADER
from pytrat.policy.compiler import CompiledPolicy
from pytrat.policy.evaluator import AuthorizationRequest

type VerifyFunction = Callable[[str], VerifiedToken]
"""Turns a raw token into a :class:`VerifiedToken` or raises ``TokenError``."""


@dataclass(frozen=True, slots=True)
class Transaction:
    """An authorized request: the verified token, the authenticated caller and the decision.

    Handlers receive this; they never see the raw token.
    """

    token: VerifiedToken
    caller: WorkloadIdentity | None
    policy_id: str
    binding: BindingResult | None

    @property
    def id(self) -> str:
        """The transaction identifier (``txn``)."""
        return self.token.claims.txn

    @property
    def claims(self) -> TransactionClaims:
        """The verified claims."""
        return self.token.claims

    @property
    def subject(self) -> str:
        """The transaction principal (``sub``)."""
        return self.token.claims.sub

    @property
    def scope(self) -> Scope:
        """The token scope."""
        return self.token.claims.scope

    @property
    def tctx(self) -> JsonObject | None:
        """The authorized transaction context."""
        return self.token.claims.tctx


class TransactionEnforcer:
    """Runs the enforcement pipeline for one service.

    Args:
        service: Service name recorded in audit events.
        verify: A :class:`TokenVerifier` or any function with the same contract (for example one
            that refreshes a remote JWKS on an unknown ``kid``).
        authenticator: Authenticates the calling workload. Required by any policy that sets
            ``require_workload_identity`` (the default); without it such policies deny.
        audit: Destination for audit events.
    """

    __slots__ = ("_audit", "_authenticator", "_service", "_verify")

    def __init__(
        self,
        *,
        service: str,
        verify: TokenVerifier | VerifyFunction,
        authenticator: WorkloadAuthenticator | None = None,
        audit: AuditSink | None = None,
    ) -> None:
        self._service = service
        self._verify: VerifyFunction = (
            verify.verify if isinstance(verify, TokenVerifier) else verify
        )
        self._authenticator = authenticator
        self._audit: AuditSink = audit or NullSink()

    @property
    def service(self) -> str:
        """Service name used in audit events."""
        return self._service

    def enforce(
        self,
        policy: CompiledPolicy,
        request: InboundRequest,
        request_data: Mapping[str, object],
        *,
        operation: str | None = None,
    ) -> Transaction | None:
        """Authorize one request.

        Returns:
            The :class:`Transaction`, or None for a policy that does not require one.

        Raises:
            TokenError: Missing, repeated or invalid ``Txn-Token`` (HTTP 401).
            AuthenticationError: Invalid or missing workload credentials (HTTP 401).
            AuthorizationError: Policy denial (HTTP 403).
            DependencyError: A required dependency is unavailable (HTTP 503).
        """
        token: VerifiedToken | None = None
        if policy.require_transaction:
            token = self._verified_token(request, policy)
        caller: WorkloadIdentity | None = None
        try:
            caller = self._authenticator.authenticate(request) if self._authenticator else None
            decision = policy.enforce(
                AuthorizationRequest(
                    token=token,
                    caller=caller.id if caller else None,
                    request_data=request_data,
                    operation=operation,
                )
            )
        except PyTraTError as error:
            self._emit(
                EventType.AUTHORIZATION_DENIED, policy, token=token, caller=caller, error=error
            )
            raise
        self._emit(
            EventType.AUTHORIZATION_GRANTED,
            policy,
            token=token,
            caller=caller,
            binding=decision.binding,
        )
        if token is None:
            return None
        return Transaction(
            token=token, caller=caller, policy_id=policy.policy_id, binding=decision.binding
        )

    def _verified_token(self, request: InboundRequest, policy: CompiledPolicy) -> VerifiedToken:
        try:
            raw = request.single(TXN_TOKEN_HEADER)  # §12.1: exactly one token
            if raw is None:
                raise TokenError(ReasonCode.TOKEN_MISSING, "Txn-Token header is required")  # noqa: TRY301 - audited below like every other token failure
            return self._verify(raw)
        except TokenError as error:
            self._emit(EventType.TOKEN_REJECTED, policy, error=error)
            raise

    def _emit(
        self,
        event_type: EventType,
        policy: CompiledPolicy,
        *,
        token: VerifiedToken | None = None,
        caller: WorkloadIdentity | None = None,
        error: PyTraTError | None = None,
        binding: BindingResult | None = None,
    ) -> None:
        detail: dict[str, str] = {}
        if error is not None:
            detail["check"] = error.detail
        if binding is not None and binding.checked:
            detail["bound_fields"] = ",".join(binding.checked)
            if binding.transforms:
                detail["transforms"] = ",".join(binding.transforms)
        self._audit.emit(
            AuditEvent.for_claims(
                event_type,
                service=self._service,
                claims=token.claims if token else None,
                token_digest=token.digest if token else None,
                policy_id=policy.policy_id,
                reason_code=error.reason if error else None,
                caller_workload=caller.id if caller else None,
                detail=detail,
            )
        )
