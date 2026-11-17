"""OpenTelemetry audit sink wired into FastAPI enforcement end to end.

The audit event, the span event and the request span describe the same decision with the same
trace id; a failing telemetry pipeline never changes the decision.
"""

# No ``from __future__ import annotations``: FastAPI must resolve the local dependency annotation.
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Annotated

import httpx
import pytest
from fastapi import Depends, FastAPI
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from pytrat.core import AuditEvent, EventType, MemorySink, ReasonCode
from pytrat.core.testing import TokenFactory
from pytrat.fastapi import PyTraT, Transaction
from pytrat.otel import OpenTelemetryAuditSink

pytestmark = pytest.mark.integration

SERVICE = "ledger-service"


@dataclass
class Tee:
    sinks: tuple[object, ...]

    def emit(self, event: AuditEvent) -> None:
        for sink in self.sinks:
            sink.emit(event)  # type: ignore[attr-defined]


@dataclass
class Stack:
    factory: TokenFactory = field(default_factory=TokenFactory.create)
    spans: InMemorySpanExporter = field(default_factory=InMemorySpanExporter)
    reader: InMemoryMetricReader = field(default_factory=InMemoryMetricReader)
    memory: MemorySink = field(default_factory=MemorySink)

    def __post_init__(self) -> None:
        self.tracer_provider = TracerProvider()
        self.tracer_provider.add_span_processor(SimpleSpanProcessor(self.spans))
        self.otel = OpenTelemetryAuditSink(
            tracer_provider=self.tracer_provider,
            meter_provider=MeterProvider(metric_readers=[self.reader]),
        )

    def app(self, audit: object) -> tuple[FastAPI, PyTraT]:
        pytrat = PyTraT(
            service=SERVICE,
            verifier=self.factory.verifier(),
            audit=audit,  # type: ignore[arg-type]
            protected_prefixes=("/internal",),
        )
        app = FastAPI(lifespan=pytrat.lifespan)
        pytrat.install(app)
        requirement = pytrat.require_transaction(
            scope="payments.transfer", require_workload_identity=False
        )

        @app.get("/internal/balance")
        async def balance(txn: Annotated[Transaction, Depends(requirement)]) -> dict[str, str]:
            return {"txn": txn.id}

        return app, pytrat


@asynccontextmanager
async def client(app: FastAPI, pytrat: PyTraT) -> AsyncIterator[httpx.AsyncClient]:
    async with (
        pytrat.lifespan(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://ledger.internal"
        ) as http,
    ):
        yield http


async def test_granted_request_audit_event_trace_id_matches_the_request_span() -> None:
    stack = Stack()
    app, pytrat = stack.app(Tee((stack.memory, stack.otel)))
    tracer = stack.tracer_provider.get_tracer("test")
    async with client(app, pytrat) as http:
        with tracer.start_as_current_span("GET /internal/balance"):
            response = await http.get(
                "/internal/balance", headers={"Txn-Token": stack.factory.mint(txn="txn-otel")}
            )
    assert response.status_code == 200

    [audit] = stack.memory.events
    [span] = stack.spans.get_finished_spans()
    assert audit.trace_id == f"{span.context.trace_id:032x}"
    [event] = span.events
    assert event.name == "pytrat.authorization.granted"
    attributes = dict(event.attributes or {})
    assert attributes["pytrat.transaction.id"] == "txn-otel"
    assert attributes["pytrat.token.digest"] == audit.token_digest
    assert attributes["pytrat.decision"] == "allow"


async def test_denied_request_is_counted_and_recorded_on_the_request_span() -> None:
    stack = Stack()
    app, pytrat = stack.app(Tee((stack.memory, stack.otel)))
    tracer = stack.tracer_provider.get_tracer("test")
    token = stack.factory.mint(scope="payments.read")
    async with client(app, pytrat) as http:
        with tracer.start_as_current_span("GET /internal/balance"):
            response = await http.get("/internal/balance", headers={"Txn-Token": token})
    assert response.status_code == 403

    [audit] = stack.memory.events
    assert audit.event_type is EventType.AUTHORIZATION_DENIED
    [span] = stack.spans.get_finished_spans()
    assert audit.trace_id == f"{span.context.trace_id:032x}"
    [event] = span.events
    assert event.attributes is not None
    assert event.attributes["pytrat.reason_code"] == ReasonCode.SCOPE_INSUFFICIENT.value
    for value in event.attributes.values():
        assert token not in str(value)

    data = stack.reader.get_metrics_data()
    assert data is not None
    [metric] = data.resource_metrics[0].scope_metrics[0].metrics
    assert metric.name == "pytrat.authorization.decisions"
    [point] = metric.data.data_points  # type: ignore[union-attr]
    assert dict(point.attributes or {}) == {
        "pytrat.decision": "deny",
        "pytrat.reason_code": "SCOPE_INSUFFICIENT",
        "pytrat.service": SERVICE,
    }
    assert point.value == 1  # type: ignore[union-attr]


class _BrokenTracer:
    def start_span(self, *args: object, **kwargs: object) -> object:
        raise RuntimeError("collector unreachable")


class _BrokenTracerProvider:
    def get_tracer(self, *args: object, **kwargs: object) -> _BrokenTracer:
        return _BrokenTracer()


async def test_broken_telemetry_never_turns_a_denial_into_an_allow() -> None:
    stack = Stack()
    broken = OpenTelemetryAuditSink(
        tracer_provider=_BrokenTracerProvider(),  # type: ignore[arg-type]
        meter_provider=MeterProvider(),
    )
    app, pytrat = stack.app(Tee((broken, stack.memory)))
    async with client(app, pytrat) as http:
        denied = await http.get(
            "/internal/balance", headers={"Txn-Token": stack.factory.mint(scope="payments.read")}
        )
        allowed = await http.get("/internal/balance", headers={"Txn-Token": stack.factory.mint()})
        missing = await http.get("/internal/balance")
    assert (denied.status_code, allowed.status_code, missing.status_code) == (403, 200, 401)
    assert broken.failed == 3
    assert [event.event_type for event in stack.memory.events] == [
        EventType.AUTHORIZATION_DENIED,
        EventType.AUTHORIZATION_GRANTED,
        EventType.TOKEN_REJECTED,
    ]
