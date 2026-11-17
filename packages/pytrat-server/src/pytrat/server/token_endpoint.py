"""The token-endpoint pipeline: a thin async shell around the pure stages.

```
parse_token_request → authenticate → rate limit → classify (issue | replace)
  issue:   validate subject → plan_issuance  → sign → record
  replace: verify Txn-Token → plan_replacement → sign → record
```

Every outcome, success or denial, is appended to the issuance log. A token is returned only after
its issuance has been recorded. Nothing here logs or records a token; only digests.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import weakref
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Final

from pytrat.core.audit import AuditEvent, AuditSink, EventType
from pytrat.core.claims import TransactionClaims
from pytrat.core.clock import Clock
from pytrat.core.constants import EXCHANGE_RESPONSE_TOKEN_TYPE, TOKEN_TYPE_TXN_TOKEN
from pytrat.core.errors import PyTraTError, ReasonCode
from pytrat.core.keys import StaticKeySet
from pytrat.core.secret import SecretToken
from pytrat.server.agent_profile import AgentProfile
from pytrat.server.audit_store import AuditRecorder, IssuanceLog
from pytrat.server.errors import OAuthError, OAuthErrorCode, translate
from pytrat.server.forms import TokenRequest, parse_token_request
from pytrat.server.ids import new_txn_id
from pytrat.server.issuance import plan_issuance
from pytrat.server.issuance_policy import IssuancePolicy
from pytrat.server.ratelimit import RateLimiter
from pytrat.server.replacement import plan_replacement, txn_token_verifier, verify_txn_token
from pytrat.server.settings import TtsSettings
from pytrat.server.signing import Signer
from pytrat.server.subjects import SubjectTokenValidator
from pytrat.server.workloads import Headers, WorkloadAuthenticator, WorkloadIdentity

__all__ = ["TokenEndpoint", "TokenResponse", "TtsComponents"]

_logger = logging.getLogger(__name__)

_SERVICE: Final = "pytrat-tts"


@dataclass(frozen=True, slots=True)
class TtsComponents:
    """Every collaborator of the TTS, injected so tests can substitute fakes.

    Attributes:
        settings: Validated settings.
        signer: Signs Txn-Tokens and publishes the JWKS.
        authenticator: Workload authentication.
        subject_validators: Validators keyed by ``subject_token_type``.
        issuance_policy: Per-workload issuance rules.
        log: The hash-chained issuance log.
        sink: Additional audit destination.
        clock: Time source.
        rate_limiter: Per-workload limiter.
        agent_profile: The agent profile, or ``None`` when disabled.
        txn_ids: Factory for new ``txn`` values.
        on_shutdown: Async callbacks run when the app stops (e.g. closing the log).
    """

    settings: TtsSettings
    signer: Signer
    authenticator: WorkloadAuthenticator
    subject_validators: Mapping[str, SubjectTokenValidator]
    issuance_policy: IssuancePolicy
    log: IssuanceLog
    sink: AuditSink
    clock: Clock
    rate_limiter: RateLimiter
    agent_profile: AgentProfile | None = None
    txn_ids: Callable[[], str] = new_txn_id
    on_shutdown: tuple[Callable[[], Awaitable[None]], ...] = ()


@dataclass(frozen=True, slots=True)
class TokenResponse:
    """A successful Txn-Token Response (txn-tokens-11 §11.4)."""

    access_token: SecretToken = field(repr=False)
    expires_in: int

    def to_dict(self) -> dict[str, object]:
        """The JSON body. txn-tokens-11 §11.4: ``token_type`` N_A, no ``refresh_token``."""
        return {
            "access_token": self.access_token.reveal(),
            "issued_token_type": TOKEN_TYPE_TXN_TOKEN,
            "token_type": EXCHANGE_RESPONSE_TOKEN_TYPE,
            "expires_in": self.expires_in,
        }


@dataclass(slots=True)
class _Progress:
    """What is known about a request so far, for the denial audit record."""

    replacement: bool = False
    workload: str | None = None
    txn: str | None = None
    subject_digest: str | None = None


def claims_digest(claims: TransactionClaims) -> str:
    """SHA-256 over the canonical JSON of the signed claims."""
    canonical = json.dumps(claims.to_payload(), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


class TokenEndpoint:
    """Runs the issuance and replacement pipeline for one request."""

    __slots__ = ("_audit", "_c", "_replacement_locks", "_verifier")

    def __init__(self, components: TtsComponents) -> None:
        self._c = components
        # Input Txn-Tokens verify against this TTS's own published keys only.
        own_keys = StaticKeySet.from_jwks(components.signer.jwks())
        self._verifier = txn_token_verifier(components.settings, own_keys, components.clock)
        self._audit = AuditRecorder(components.log, components.sink)
        # One lock per txn makes count -> plan -> sign -> record atomic within this process, so
        # concurrent replacements cannot all pass the replacement limit (security review #5).
        # Multi-instance deployments additionally need the shared IssuanceLog to enforce it.
        self._replacement_locks: weakref.WeakValueDictionary[str, asyncio.Lock] = (
            weakref.WeakValueDictionary()
        )

    def _replacement_lock(self, txn: str) -> asyncio.Lock:
        lock = self._replacement_locks.get(txn)
        if lock is None:
            lock = asyncio.Lock()
            self._replacement_locks[txn] = lock
        return lock

    async def handle(
        self, raw_body: bytes, content_type: str | None, headers: Headers, peer: str | None
    ) -> TokenResponse:
        """Process one token request.

        Raises:
            OAuthError: For every rejection, after it has been recorded.
        """
        progress = _Progress()
        try:
            request = parse_token_request(
                raw_body, content_type, max_bytes=self._c.settings.max_request_bytes
            )
            progress.replacement = request.is_replacement
            progress.subject_digest = request.subject_token.digest
            # txn-tokens-11 §11.3, §11.5: authenticate the requesting workload first.
            workload = self._c.authenticator.authenticate(request, headers, peer)
            progress.workload = workload.id
            self._c.rate_limiter.acquire(workload.id)
            if request.is_replacement:
                return await self._replace(request, workload, progress)
            return await self._issue(request, workload, progress)
        except OAuthError as exc:
            await self._record_rejection(exc, progress)
            raise
        except PyTraTError as exc:
            error = translate(exc, OAuthErrorCode.SERVER_ERROR)
            await self._record_rejection(error, progress)
            raise error from None

    async def _issue(
        self, request: TokenRequest, workload: WorkloadIdentity, progress: _Progress
    ) -> TokenResponse:
        validator = self._c.subject_validators.get(request.subject_token_type)
        if validator is None:
            raise OAuthError(
                OAuthErrorCode.INVALID_REQUEST,
                "subject_token_type is not supported",
                ReasonCode.TOKEN_TYPE_INVALID,
            )
        subject = validator.validate(request.subject_token, workload)
        progress.txn = self._c.txn_ids()
        plan = plan_issuance(
            request,
            workload,
            subject,
            self._c.issuance_policy,
            self._c.settings,
            self._c.clock,
            progress.txn,
            agents=self._c.agent_profile,
        )
        detail = {"subject_token_type": request.subject_token_type}
        return await self._sign_and_record(
            EventType.TOKEN_ISSUED, plan.claims, workload, plan.dropped_keys, detail
        )

    async def _replace(
        self, request: TokenRequest, workload: WorkloadIdentity, progress: _Progress
    ) -> TokenResponse:
        current = verify_txn_token(self._verifier, request.subject_token)
        progress.txn = current.claims.txn
        async with self._replacement_lock(current.claims.txn):
            count = await self._c.log.replacement_count(current.claims.txn)
            plan = plan_replacement(
                current,
                request,
                workload,
                self._c.issuance_policy,
                self._c.settings,
                self._c.clock,
                count,
                agents=self._c.agent_profile,
            )
            detail = {"replaced_token_digest": current.digest}
            if plan.extends_lifetime:
                detail["lifetime"] = "extended"
            return await self._sign_and_record(
                EventType.TOKEN_REPLACED, plan.claims, workload, plan.dropped_keys, detail
            )

    async def _sign_and_record(
        self,
        event_type: EventType,
        claims: TransactionClaims,
        workload: WorkloadIdentity,
        dropped_keys: tuple[str, ...],
        detail: dict[str, str],
    ) -> TokenResponse:
        token = SecretToken(self._c.signer.sign(claims.to_payload()))
        if dropped_keys:
            detail["dropped_keys"] = ",".join(dropped_keys)
        event = AuditEvent.for_claims(
            event_type,
            service=_SERVICE,
            claims=claims,
            token_digest=token.digest,
            caller_workload=workload.id,
            timestamp=self._timestamp(),
            detail=detail,
        )
        # PyTraT profile P9: the call chain is kept in the log, so an unrecorded token is never
        # released.
        await self._audit.record_success(event, claims_digest(claims))
        _logger.info(
            "%s txn=%s workload=%s token_sha256=%s",
            event_type.value,
            claims.txn,
            workload.id,
            token.digest,
        )
        return TokenResponse(access_token=token, expires_in=claims.exp - claims.iat)

    async def record_rejection(self, error: OAuthError) -> None:
        """Record a denial that happened before the pipeline started. Never raises."""
        await self._record_rejection(error, _Progress())

    async def _record_rejection(self, error: OAuthError, progress: _Progress) -> None:
        event = AuditEvent(
            event_type=(
                EventType.REPLACEMENT_DENIED if progress.replacement else EventType.ISSUANCE_DENIED
            ),
            service=_SERVICE,
            timestamp=self._timestamp(),
            transaction_id=progress.txn,
            reason_code=error.reason,
            requesting_workload=progress.workload,
            caller_workload=progress.workload,
            token_digest=progress.subject_digest,
            detail={"error": error.error.value},
        )
        await self._audit.record_denial(event)
        _logger.info(
            "token request denied error=%s reason=%s workload=%s txn=%s",
            error.error.value,
            error.reason.value,
            progress.workload,
            progress.txn,
        )

    def _timestamp(self) -> datetime:
        return datetime.fromtimestamp(self._c.clock.now(), UTC)
