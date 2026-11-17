"""OpenTelemetryAuditSink: exact span events, exact metric points, token guard, failure handling."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from types import MappingProxyType

import pytest
from hypothesis import given
from hypothesis import strategies as st
from opentelemetry import trace
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import NonRecordingSpan, SpanContext, TraceFlags

from pytrat.core import AgentAuditContext, AuditEvent, EventType, ReasonCode
from pytrat.core.testing import TokenFactory, b64url
from pytrat.otel import OpenTelemetryAuditSink, looks_like_jose, semconv
from pytrat.otel._attributes import OUTCOMES

MOMENT = datetime(2026, 11, 17, 12, 0, 0, 123456, tzinfo=UTC)
MOMENT_NS = 1_794_916_800_123_456_000


class Telemetry:
    def __init__(self) -> None:
        self.spans = InMemorySpanExporter()
        self.tracer_provider = TracerProvider()
        self.tracer_provider.add_span_processor(SimpleSpanProcessor(self.spans))
        self.reader = InMemoryMetricReader()
        self.meter_provider = MeterProvider(metric_readers=[self.reader])
        self.sink = OpenTelemetryAuditSink(
            tracer_provider=self.tracer_provider, meter_provider=self.meter_provider
        )

    def points(self) -> dict[str, list[tuple[dict[str, object], int]]]:
        data = self.reader.get_metrics_data()
        found: dict[str, list[tuple[dict[str, object], int]]] = {}
        if data is None:
            return found
        for resource in data.resource_metrics:
            for scope in resource.scope_metrics:
                assert scope.scope.name == "pytrat.otel"
                for metric in scope.metrics:
                    assert metric.unit == "{decision}"
                    found[metric.name] = [
                        (dict(point.attributes or {}), point.value)
                        for point in metric.data.data_points  # type: ignore[union-attr]
                    ]
        return found


@pytest.fixture
def otel() -> Telemetry:
    return Telemetry()


def full_event(**overrides: object) -> AuditEvent:
    fields: dict[str, object] = {
        "event_type": EventType.AUTHORIZATION_DENIED,
        "service": "ledger-service",
        "timestamp": MOMENT,
        "transaction_id": "txn-123",
        "subject": "user:alice",
        "scope": "payments.transfer",
        "policy_id": "transfer",
        "reason_code": ReasonCode.TRANSACTION_CONTEXT_MISMATCH,
        "requesting_workload": "api-gateway",
        "caller_workload": "payment-service",
        "token_digest": "a" * 64,
        "agent_context": AgentAuditContext(
            originator="user:alice",
            proximate="agent:planner",
            hop_count=2,
            min_assurance_level="high",
        ),
        "trace_id": None,
        "detail": MappingProxyType({"check": "tctx.amount_minor", "bound_fields": "amount_minor"}),
        **overrides,
    }
    return AuditEvent(**fields)  # type: ignore[arg-type]


FULL_ATTRIBUTES = {
    "pytrat.audit.schema_version": 1,
    "pytrat.event.type": "authorization.denied",
    "pytrat.decision": "deny",
    "pytrat.reason_code": "TRANSACTION_CONTEXT_MISMATCH",
    "pytrat.service": "ledger-service",
    "pytrat.transaction.id": "txn-123",
    "pytrat.scope": "payments.transfer",
    "pytrat.policy.id": "transfer",
    "pytrat.workload.requesting": "api-gateway",
    "pytrat.workload.caller": "payment-service",
    "pytrat.token.digest": "a" * 64,
    "pytrat.agent.originator": "user:alice",
    "pytrat.agent.proximate": "agent:planner",
    "pytrat.agent.hop_count": 2,
    "pytrat.agent.min_assurance_level": "high",
    "pytrat.detail.check": "tctx.amount_minor",
    "pytrat.detail.bound_fields": "amount_minor",
}


# ------------------------------------------------------------------ spans


def test_event_is_added_to_the_current_recording_span_with_exact_attributes(
    otel: Telemetry,
) -> None:
    tracer = otel.tracer_provider.get_tracer("app")
    with tracer.start_as_current_span("POST /internal/transfer"):
        otel.sink.emit(full_event())
    [span] = otel.spans.get_finished_spans()
    assert span.name == "POST /internal/transfer"
    [event] = span.events
    assert event.name == "pytrat.authorization.denied"
    assert event.timestamp == MOMENT_NS
    assert dict(event.attributes or {}) == FULL_ATTRIBUTES
    assert otel.sink.failed == 0
    assert otel.sink.redacted == 0


def test_subject_is_never_exported(otel: Telemetry) -> None:
    otel.sink.emit(full_event(subject="user:bob-unique-subject"))
    [span] = otel.spans.get_finished_spans()
    exported = [*span.events[0].attributes.values(), *span.attributes.values()]  # type: ignore[union-attr]
    assert "user:bob-unique-subject" not in exported


def test_without_an_active_span_a_short_audit_span_carries_the_event(otel: Telemetry) -> None:
    otel.sink.emit(full_event())
    [span] = otel.spans.get_finished_spans()
    assert span.name == "pytrat.audit"
    assert span.kind is trace.SpanKind.INTERNAL
    assert span.parent is None
    assert span.start_time == MOMENT_NS
    assert dict(span.attributes or {}) == FULL_ATTRIBUTES
    [event] = span.events
    assert event.name == "pytrat.authorization.denied"
    assert dict(event.attributes or {}) == FULL_ATTRIBUTES


def test_a_sampled_out_parent_also_samples_out_the_audit_span(otel: Telemetry) -> None:
    parent = NonRecordingSpan(
        SpanContext(trace_id=0x1234, span_id=0x5678, is_remote=True, trace_flags=TraceFlags(0))
    )
    with trace.use_span(parent):
        otel.sink.emit(full_event())
    assert otel.spans.get_finished_spans() == ()
    # Metrics are not sampled.
    assert otel.points()[semconv.AUTHORIZATION_DECISIONS][0][1] == 1


def test_absent_optional_fields_are_omitted(otel: Telemetry) -> None:
    otel.sink.emit(
        AuditEvent(
            event_type=EventType.TOKEN_REJECTED,
            service="ledger-service",
            timestamp=MOMENT,
            reason_code=ReasonCode.TOKEN_MISSING,
            trace_id=None,
        )
    )
    [span] = otel.spans.get_finished_spans()
    assert dict(span.events[0].attributes or {}) == {
        "pytrat.audit.schema_version": 1,
        "pytrat.event.type": "token.rejected",
        "pytrat.decision": "deny",
        "pytrat.reason_code": "TOKEN_MISSING",
        "pytrat.service": "ledger-service",
    }


def test_agent_without_assurance_level_omits_it(otel: Telemetry) -> None:
    agent = AgentAuditContext(originator="user:alice", proximate="agent:a", hop_count=1)
    otel.sink.emit(full_event(agent_context=agent))
    attributes = dict(otel.spans.get_finished_spans()[0].events[0].attributes or {})
    assert attributes["pytrat.agent.hop_count"] == 1
    assert "pytrat.agent.min_assurance_level" not in attributes


# ------------------------------------------------------------------ metrics


def test_every_event_type_has_a_counter_and_decision() -> None:
    assert set(OUTCOMES) == set(EventType)


@pytest.mark.parametrize(
    ("event_type", "counter", "decision"),
    [
        (EventType.AUTHORIZATION_GRANTED, "pytrat.authorization.decisions", "allow"),
        (EventType.AUTHORIZATION_DENIED, "pytrat.authorization.decisions", "deny"),
        (EventType.TOKEN_REJECTED, "pytrat.authorization.decisions", "deny"),
        (EventType.TOKEN_ISSUED, "pytrat.issuance.decisions", "allow"),
        (EventType.ISSUANCE_DENIED, "pytrat.issuance.decisions", "deny"),
        (EventType.TOKEN_REPLACED, "pytrat.replacement.decisions", "allow"),
        (EventType.REPLACEMENT_DENIED, "pytrat.replacement.decisions", "deny"),
    ],
)
def test_each_event_increments_exactly_one_counter_with_bounded_attributes(
    otel: Telemetry, event_type: EventType, counter: str, decision: str
) -> None:
    otel.sink.emit(full_event(event_type=event_type, reason_code=ReasonCode.SCOPE_INSUFFICIENT))
    otel.sink.emit(full_event(event_type=event_type, reason_code=ReasonCode.SCOPE_INSUFFICIENT))
    points = otel.points()
    assert {name for name, values in points.items() if values} == {counter}
    assert points[counter] == [
        (
            {
                "pytrat.decision": decision,
                "pytrat.reason_code": "SCOPE_INSUFFICIENT",
                "pytrat.service": "ledger-service",
            },
            2,
        )
    ]


def test_allow_without_reason_code_has_no_reason_attribute(otel: Telemetry) -> None:
    otel.sink.emit(full_event(event_type=EventType.AUTHORIZATION_GRANTED, reason_code=None))
    assert otel.points()[semconv.AUTHORIZATION_DECISIONS] == [
        ({"pytrat.decision": "allow", "pytrat.service": "ledger-service"}, 1)
    ]


# ------------------------------------------------------------------ token guard

FACTORY = TokenFactory.create()
SIGNED = FACTORY.mint(txn="txn-guard")
UNSIGNED = FACTORY.unsigned()
SPACED_HEADER = b64url(b'{ "alg": "ES256" }')
NEWLINE_HEADER = b64url(b'{\n"alg":"ES256"}')


@pytest.mark.parametrize(
    "smuggled",
    [
        SIGNED,
        UNSIGNED,
        f"Bearer {SIGNED}",
        SIGNED.replace("-", "+").replace("_", "/"),
        f"{SPACED_HEADER}.{b64url(b'{}')}.sig",
        f"{NEWLINE_HEADER}..detached",
    ],
    ids=["signed", "alg-none", "embedded", "standard-base64", "spaced-header", "detached"],
)
def test_token_smuggled_into_any_string_field_never_reaches_telemetry(
    otel: Telemetry, smuggled: str, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    otel.sink.emit(
        full_event(
            scope=smuggled,
            policy_id=smuggled,
            service=smuggled,
            transaction_id=smuggled,
            detail={"check": smuggled, smuggled: "value", "kept": "tctx.currency"},
        )
    )
    [span] = otel.spans.get_finished_spans()
    exported = {**dict(span.attributes or {}), **dict(span.events[0].attributes or {})}
    for name, value in exported.items():
        assert smuggled not in name
        assert smuggled not in str(value)
    assert exported["pytrat.detail.kept"] == "tctx.currency"
    for absent in ("pytrat.scope", "pytrat.policy.id", "pytrat.service", "pytrat.transaction.id"):
        assert absent not in exported
    assert "pytrat.detail.check" not in exported
    assert otel.sink.redacted == 6
    assert smuggled not in caplog.text
    assert "pytrat.detail.*" in caplog.text
    for points in otel.points().values():
        for attributes, _ in points:
            assert smuggled not in attributes.values()


@pytest.mark.parametrize(
    "benign",
    [
        "payments.transfer.read",
        "a" * 64,
        "txn-0f3a9c",
        "tctx.amount_minor",
        "every.thing.is.fine",
        "spiffe://payments.internal/ns/default/sa/ledger",
        "eyes.only.",
    ],
)
def test_ordinary_identifiers_are_not_mistaken_for_tokens(benign: str) -> None:
    assert not looks_like_jose(benign)


@given(
    header=st.dictionaries(st.text(min_size=1), st.text() | st.integers(), max_size=4).map(
        lambda extra: {"alg": "ES256", **extra}
    ),
    payload=st.binary(max_size=64),
    signature=st.binary(max_size=64),
    indent=st.sampled_from([None, 1, "\t"]),
)
def test_any_compact_serialization_is_recognised(
    header: dict[str, object], payload: bytes, signature: bytes, indent: int | str | None
) -> None:
    raw_header = json.dumps(header, indent=indent).encode()
    assert looks_like_jose(f"{b64url(raw_header)}.{b64url(payload)}.{b64url(signature)}")


# ------------------------------------------------------------------ failures


class _ExplodingCounter:
    def add(self, amount: int, attributes: object = None) -> None:
        raise RuntimeError(f"export failed for {SIGNED}")


class _ExplodingMeter:
    def create_counter(self, name: str, unit: str = "", description: str = "") -> object:
        return _ExplodingCounter()


class _ExplodingMeterProvider:
    def get_meter(self, *args: object, **kwargs: object) -> _ExplodingMeter:
        return _ExplodingMeter()


def test_exporter_failure_is_counted_and_logged_without_its_message(
    caplog: pytest.LogCaptureFixture,
) -> None:
    sink = OpenTelemetryAuditSink(meter_provider=_ExplodingMeterProvider())  # type: ignore[arg-type]
    caplog.set_level(logging.ERROR, logger="pytrat.otel")
    sink.emit(full_event())
    assert sink.failed == 1
    assert "OpenTelemetry audit export failed: RuntimeError" in caplog.text
    assert SIGNED not in caplog.text
    assert "Traceback" not in caplog.text


def test_default_global_providers_work_without_an_sdk() -> None:
    sink = OpenTelemetryAuditSink()
    sink.emit(full_event())
    assert sink.failed == 0
