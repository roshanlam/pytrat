"""Structured audit events.

Every authorization decision and every issuance or replacement produces one :class:`AuditEvent`.
Events never contain tokens, key material, or the values of bound parameters: only identifiers,
reason codes, field paths and the token digest (txn-tokens-11 §15.2).

Sinks must never block the request path and must never raise. An audit outage must not become a
request outage, but dropped events are counted and reported.
"""

from __future__ import annotations

import json
import logging
import queue
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, Protocol

from pytrat.core.errors import ReasonCode

if TYPE_CHECKING:
    from pytrat.core.claims import TransactionClaims

_logger = logging.getLogger(__name__)

SCHEMA_VERSION: Final = 1


class EventType(StrEnum):
    """Audit event types (schema version 1)."""

    AUTHORIZATION_GRANTED = "authorization.granted"
    AUTHORIZATION_DENIED = "authorization.denied"
    TOKEN_REJECTED = "token.rejected"
    TOKEN_ISSUED = "token.issued"
    TOKEN_REPLACED = "token.replaced"
    ISSUANCE_DENIED = "issuance.denied"
    REPLACEMENT_DENIED = "replacement.denied"


def current_trace_id() -> str | None:
    """Return the active OpenTelemetry trace id, if OpenTelemetry is installed and tracing."""
    try:
        from opentelemetry import trace  # type: ignore[import-not-found, unused-ignore]  # noqa: PLC0415
    except ImportError:
        return None
    context = trace.get_current_span().get_span_context()
    return f"{context.trace_id:032x}" if context.is_valid else None


@dataclass(frozen=True, slots=True)
class AgentAuditContext:
    """Agent chain summary. ``session_id`` values are deliberately not recorded."""

    originator: str
    proximate: str
    hop_count: int
    min_assurance_level: str | None = None

    @classmethod
    def from_claims(cls, claims: TransactionClaims) -> AgentAuditContext | None:
        """Summarise ``agentic_ctx`` if present."""
        ctx = claims.agentic_ctx
        if ctx is None:
            return None
        return cls(
            originator=ctx.originator.id,
            proximate=ctx.proximate_agent.id,
            hop_count=ctx.chain_metadata.hop_count,
            min_assurance_level=ctx.chain_metadata.min_assurance_level,
        )


_EMPTY: Final[Mapping[str, str]] = MappingProxyType({})


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """One machine-readable audit record.

    ``detail`` holds field paths, transform names and similar labels, never values.
    """

    event_type: EventType
    service: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    transaction_id: str | None = None
    subject: str | None = None
    scope: str | None = None
    policy_id: str | None = None
    reason_code: ReasonCode | None = None
    requesting_workload: str | None = None
    caller_workload: str | None = None
    token_digest: str | None = None
    agent_context: AgentAuditContext | None = None
    trace_id: str | None = field(default_factory=current_trace_id)
    detail: Mapping[str, str] = _EMPTY

    @classmethod
    def for_claims(
        cls,
        event_type: EventType,
        *,
        service: str,
        claims: TransactionClaims | None,
        token_digest: str | None = None,
        **fields: object,
    ) -> AuditEvent:
        """Build an event populated from verified claims."""
        base: dict[str, object] = {}
        if claims is not None:
            base = {
                "transaction_id": claims.txn,
                "subject": claims.sub,
                "scope": str(claims.scope),
                "requesting_workload": claims.req_wl,
                "agent_context": AgentAuditContext.from_claims(claims),
            }
        return cls(
            event_type=event_type,
            service=service,
            token_digest=token_digest,
            **{**base, **fields},  # type: ignore[arg-type]  # validated by dataclass fields
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise to a JSON-compatible dict, omitting absent fields."""
        data: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            "service": self.service,
        }
        optional: dict[str, object | None] = {
            "transaction_id": self.transaction_id,
            "subject": self.subject,
            "scope": self.scope,
            "policy_id": self.policy_id,
            "reason_code": self.reason_code.value if self.reason_code else None,
            "requesting_workload": self.requesting_workload,
            "caller_workload": self.caller_workload,
            "token_digest": self.token_digest,
            "trace_id": self.trace_id,
        }
        data.update({key: value for key, value in optional.items() if value is not None})
        if self.agent_context is not None:
            agent: dict[str, object] = {
                "originator": self.agent_context.originator,
                "proximate": self.agent_context.proximate,
                "hop_count": self.agent_context.hop_count,
            }
            if self.agent_context.min_assurance_level is not None:
                agent["min_assurance_level"] = self.agent_context.min_assurance_level
            data["agent_context"] = agent
        if self.detail:
            data["detail"] = dict(self.detail)
        return data

    def to_json(self) -> str:
        """Serialise as one compact JSON line."""
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)


class AuditSink(Protocol):
    """Destination for audit events. ``emit`` must not block and must not raise."""

    def emit(self, event: AuditEvent) -> None:
        """Record one event."""
        ...


class NullSink:
    """Discards events."""

    __slots__ = ()

    def emit(self, event: AuditEvent) -> None:
        """Discard ``event``."""


class MemorySink:
    """Keeps events in a list. For tests and demos."""

    __slots__ = ("events",)

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        """Append ``event``."""
        self.events.append(event)

    def of_type(self, event_type: EventType) -> list[AuditEvent]:
        """Return recorded events of one type."""
        return [event for event in self.events if event.event_type is event_type]


class LoggingSink:
    """Writes events as JSON through a standard logger."""

    __slots__ = ("_level", "_logger")

    def __init__(self, logger: logging.Logger | None = None, level: int = logging.INFO) -> None:
        self._logger = logger or logging.getLogger("pytrat.audit")
        self._level = level

    def emit(self, event: AuditEvent) -> None:
        """Log ``event`` as one JSON line."""
        try:
            self._logger.log(self._level, event.to_json())
        except Exception:
            _logger.exception("audit logging failed")


class JsonLinesSink:
    """Appends events to a JSON Lines file from a background thread.

    ``emit`` only enqueues. If the queue is full the event is dropped, :attr:`dropped` is
    incremented, and a warning is logged once per overflow episode.
    """

    def __init__(self, path: str | Path, *, max_queue: int = 10_000) -> None:
        self._path = Path(path)
        self._queue: queue.Queue[AuditEvent | None] = queue.Queue(maxsize=max_queue)
        self.dropped = 0
        self._overflowing = False
        self._thread = threading.Thread(target=self._run, name="pytrat-audit", daemon=True)
        self._thread.start()

    def emit(self, event: AuditEvent) -> None:
        """Enqueue ``event`` for writing."""
        try:
            self._queue.put_nowait(event)
            self._overflowing = False
        except queue.Full:
            self.dropped += 1
            if not self._overflowing:
                self._overflowing = True
                _logger.warning("audit queue full; dropping events (dropped=%d)", self.dropped)

    def close(self, timeout: float = 5.0) -> None:
        """Flush pending events and stop the writer thread."""
        self._queue.put(None)
        self._thread.join(timeout)

    def _run(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as handle:
            while (event := self._queue.get()) is not None:
                try:
                    handle.write(event.to_json() + "\n")
                    if self._queue.empty():
                        handle.flush()
                except Exception:
                    _logger.exception("failed to write audit event")
            handle.flush()
