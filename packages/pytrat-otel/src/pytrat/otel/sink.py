"""An :class:`~pytrat.core.audit.AuditSink` that records audit events in OpenTelemetry."""

from __future__ import annotations

import logging
from types import MappingProxyType
from typing import TYPE_CHECKING

from opentelemetry import metrics, trace

from pytrat.otel import semconv
from pytrat.otel._attributes import event_attributes

if TYPE_CHECKING:
    from datetime import datetime

    from pytrat.core.audit import AuditEvent

_logger = logging.getLogger(__name__)

_COUNTERS = (
    (semconv.AUTHORIZATION_DECISIONS, "Authorization decisions taken by PyTraT enforcement."),
    (semconv.ISSUANCE_DECISIONS, "Transaction Token issuance outcomes at the TTS."),
    (semconv.REPLACEMENT_DECISIONS, "Transaction Token replacement outcomes at the TTS."),
)


class OpenTelemetryAuditSink:
    """Records each :class:`AuditEvent` as an OpenTelemetry span event and counts decisions.

    Tracing: the event is added to the current span when it is recording, so it sits on the
    request span next to the HTTP attributes and shares its trace id (the same id the
    ``AuditEvent`` carries). With no recording span, a short ``pytrat.audit`` span is started
    in the current context to carry it, so events are not lost in uninstrumented applications;
    because it is started in the current context, a sampled-out parent also samples it out.

    Metrics: one increment of ``pytrat.authorization.decisions``,
    ``pytrat.issuance.decisions`` or ``pytrat.replacement.decisions`` per event, with only the
    ``pytrat.decision``, ``pytrat.reason_code`` and ``pytrat.service`` attributes.

    Attributes are primitives built from identifiers, reason codes and digests only. Any string
    shaped like a compact JWS or JWE is withheld (and counted in :attr:`redacted`), as defence in
    depth: audit events never carry tokens, and this sink must not become the place one leaks.

    Like every :class:`~pytrat.core.audit.AuditSink`, :meth:`emit` never raises: a telemetry
    failure is logged (exception type only) and counted in :attr:`failed`. The decision has already
    been taken when the event is emitted, so a failure here can never turn a denial into an allow.

    Args:
        tracer_provider: Provider for the tracer. Defaults to the global provider.
        meter_provider: Provider for the meter. Defaults to the global provider.

    Attributes:
        failed: Events that could not be recorded.
        redacted: Attributes withheld because they looked like a token.
    """

    __slots__ = ("_counters", "_tracer", "failed", "redacted")

    def __init__(
        self,
        *,
        tracer_provider: trace.TracerProvider | None = None,
        meter_provider: metrics.MeterProvider | None = None,
    ) -> None:
        self._tracer = trace.get_tracer(
            semconv.INSTRUMENTATION_SCOPE, tracer_provider=tracer_provider
        )
        meter = metrics.get_meter(semconv.INSTRUMENTATION_SCOPE, meter_provider=meter_provider)
        self._counters = MappingProxyType(
            {
                name: meter.create_counter(
                    name, unit=semconv.DECISIONS_UNIT, description=description
                )
                for name, description in _COUNTERS
            }
        )
        self.failed = 0
        self.redacted = 0

    def emit(self, event: AuditEvent) -> None:
        """Record ``event``. Never raises."""
        try:
            self._record(event)
        except Exception as exc:  # noqa: BLE001 - sinks must not raise (pytrat.core.audit)
            self.failed += 1
            # Type only: an exporter's message could echo attribute values.
            _logger.error("OpenTelemetry audit export failed: %s", type(exc).__name__)  # noqa: TRY400

    def _record(self, event: AuditEvent) -> None:
        attributes = event_attributes(event)
        if attributes.dropped:
            self.redacted += len(attributes.dropped)
            _logger.warning(
                "withheld token-shaped audit attributes: %s", ",".join(attributes.dropped)
            )
        name = semconv.EVENT_NAME_PREFIX + event.event_type.value
        timestamp = _nanoseconds(event.timestamp)
        span = trace.get_current_span()
        if span.is_recording():
            span.add_event(name, attributes.span, timestamp=timestamp)
        else:
            audit_span = self._tracer.start_span(
                semconv.AUDIT_SPAN_NAME,
                kind=trace.SpanKind.INTERNAL,
                attributes=attributes.span,
                start_time=timestamp,
            )
            audit_span.add_event(name, attributes.span, timestamp=timestamp)
            audit_span.end()
        self._counters[attributes.counter].add(1, attributes.metric)


def _nanoseconds(moment: datetime) -> int:
    return round(moment.timestamp() * 1_000_000) * 1_000
