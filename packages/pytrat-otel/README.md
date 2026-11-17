# pytrat-otel

OpenTelemetry audit sink for PyTraT. Every audit event (authorization decision, token rejection,
issuance, replacement) becomes a span event on the current span and one increment of a decision
counter. Depends only on `opentelemetry-api`; configure the SDK and exporters in your application.

```python
from pytrat.fastapi import PyTraT
from pytrat.otel import OpenTelemetryAuditSink

pytrat = PyTraT(
    service="ledger-service",
    verifier=verifier,
    authenticator=authenticator,
    audit=OpenTelemetryAuditSink(),  # global TracerProvider / MeterProvider
    protected_prefixes=("/internal",),
)
```

Pass `tracer_provider=` / `meter_provider=` to use specific providers instead of the global ones.
The sink records telemetry, not the audit trail of record: keep a durable sink (for example
`JsonLinesSink`) as well if you need one.

| Kind | Name | Attributes |
| --- | --- | --- |
| span event | `pytrat.<event_type>` (e.g. `pytrat.authorization.denied`) | see below |
| span (only when no span is recording) | `pytrat.audit` | as the event |
| counter | `pytrat.authorization.decisions` | `pytrat.decision`, `pytrat.reason_code`, `pytrat.service` |
| counter | `pytrat.issuance.decisions` | same |
| counter | `pytrat.replacement.decisions` | same |

Span event attributes: `pytrat.audit.schema_version`, `pytrat.event.type`, `pytrat.decision`
(`allow`/`deny`), `pytrat.reason_code`, `pytrat.service`, `pytrat.transaction.id`, `pytrat.scope`,
`pytrat.policy.id`, `pytrat.workload.requesting`, `pytrat.workload.caller`, `pytrat.token.digest`,
`pytrat.agent.originator`, `pytrat.agent.proximate`, `pytrat.agent.hop_count`,
`pytrat.agent.min_assurance_level`, and `pytrat.detail.<key>` for each detail label. Absent fields
are omitted. The subject is not exported. Any string shaped like a compact JWS/JWE is withheld.

The sink never raises: telemetry failures are logged (exception type only) and counted in
`sink.failed`; withheld attributes are counted in `sink.redacted`.
