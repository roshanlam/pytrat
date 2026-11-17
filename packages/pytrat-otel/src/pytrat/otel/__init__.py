"""PyTraT OpenTelemetry: record audit events as span events and decision metrics.

Depends only on ``opentelemetry-api``; the application configures the SDK and exporters::

    from pytrat.otel import OpenTelemetryAuditSink

    pytrat = PyTraT(service="ledger", verifier=verifier, audit=OpenTelemetryAuditSink())

Attribute, span event and instrument names are in :mod:`pytrat.otel.semconv`.
"""

from pytrat.otel import semconv
from pytrat.otel._attributes import looks_like_jose
from pytrat.otel.sink import OpenTelemetryAuditSink

__all__ = ["OpenTelemetryAuditSink", "looks_like_jose", "semconv"]
