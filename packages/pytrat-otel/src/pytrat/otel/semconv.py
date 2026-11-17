"""Names of the span events, attributes and instruments that :mod:`pytrat.otel` emits.

Follows OpenTelemetry semantic-convention style: a ``pytrat.`` namespace, dot-separated
components, ``snake_case`` words. These names are public API: add, never rename.
"""

from __future__ import annotations

from typing import Final

INSTRUMENTATION_SCOPE: Final = "pytrat.otel"

# Span events
EVENT_NAME_PREFIX: Final = "pytrat."
"""Span event name is this prefix plus the audit event type, e.g. ``pytrat.token.issued``."""

AUDIT_SPAN_NAME: Final = "pytrat.audit"
"""Name of the short span recorded when no span is active."""

# Attributes
AUDIT_SCHEMA_VERSION: Final = "pytrat.audit.schema_version"
EVENT_TYPE: Final = "pytrat.event.type"
DECISION: Final = "pytrat.decision"
REASON_CODE: Final = "pytrat.reason_code"
SERVICE: Final = "pytrat.service"
TRANSACTION_ID: Final = "pytrat.transaction.id"
SCOPE: Final = "pytrat.scope"
POLICY_ID: Final = "pytrat.policy.id"
REQUESTING_WORKLOAD: Final = "pytrat.workload.requesting"
CALLER_WORKLOAD: Final = "pytrat.workload.caller"
TOKEN_DIGEST: Final = "pytrat.token.digest"
AGENT_ORIGINATOR: Final = "pytrat.agent.originator"
AGENT_PROXIMATE: Final = "pytrat.agent.proximate"
AGENT_HOP_COUNT: Final = "pytrat.agent.hop_count"
AGENT_MIN_ASSURANCE_LEVEL: Final = "pytrat.agent.min_assurance_level"
DETAIL_PREFIX: Final = "pytrat.detail."
"""Each ``AuditEvent.detail`` entry becomes ``pytrat.detail.<key>``."""

# Attribute values
DECISION_ALLOW: Final = "allow"
DECISION_DENY: Final = "deny"

# Metrics
AUTHORIZATION_DECISIONS: Final = "pytrat.authorization.decisions"
ISSUANCE_DECISIONS: Final = "pytrat.issuance.decisions"
REPLACEMENT_DECISIONS: Final = "pytrat.replacement.decisions"
DECISIONS_UNIT: Final = "{decision}"

METRIC_ATTRIBUTES: Final = (DECISION, REASON_CODE, SERVICE)
"""The only attributes put on metric points: bounded cardinality by construction."""
