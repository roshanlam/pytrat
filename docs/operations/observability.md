# Observability (OpenTelemetry)

Every authorization decision, issuance and replacement produces exactly one `AuditEvent`. The
`pytrat-otel` package exports those events to OpenTelemetry as span events and decision counters,
so they share the request's trace. It depends only on `opentelemetry-api`; configure the SDK and
exporters as usual for your application.

Audit events already carry the active trace id (`trace_id`) whenever `opentelemetry` is installed
and a span is recording, even with another sink.

What is deliberately **not** exported:

* tokens: any string attribute shaped like a compact JWS/JWE is dropped and counted in
  `sink.redacted`;
* `subject`: usually a user id, and telemetry pipelines rarely have audit-log retention and access
  controls. Correlate by `pytrat.transaction.id` instead.

The sink never raises. When it fails at a resource service, a denial keeps its own reason and a
grant that cannot be audited is refused with 503 (profile decision P35 in
[compatibility](../compatibility.md)).

--8<-- "packages/pytrat-otel/README.md:usage"
