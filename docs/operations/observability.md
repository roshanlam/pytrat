# Observability (OpenTelemetry)

!!! info "Coming with M9"
    An OpenTelemetry audit sink (`pytrat-otel`) is part of milestone M9 and is documented here when
    it lands.

Today, audit events already carry the active OpenTelemetry trace id (`trace_id`) when the
`opentelemetry` package is installed and a span is recording. Send events anywhere with a custom
`AuditSink`, or use `LoggingSink` / `JsonLinesSink`; see [Concepts](../concepts.md#audit).
