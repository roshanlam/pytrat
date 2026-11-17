"""Pure mapping from :class:`AuditEvent` to OpenTelemetry attributes. No I/O."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from pytrat.core.audit import SCHEMA_VERSION, AuditEvent, EventType
from pytrat.otel import semconv

type AttributeValue = str | int
"""The only attribute value types this package produces: primitives, never sequences."""

# A compact JWS or JWE (RFC 7515 §7.1, RFC 7516 §7.1) starts with the base64url encoding of a
# JSON object header: "{" followed by '"' or whitespace encodes to "ey" or "ew". Header plus at
# least one more dot-separated segment is enough to treat the string as a token. Standard-alphabet
# characters are accepted too, so a sloppily re-encoded token is still caught. Searched, not
# matched, so a token embedded in a longer string ("Bearer eyJ...") is caught as well.
_JOSE_SHAPE: Final = re.compile(r"e[yw][A-Za-z0-9_\-+/=]{8,}\.[A-Za-z0-9_\-+/=]*\.")

_REDACTED_DETAIL_KEY: Final = semconv.DETAIL_PREFIX + "*"


@dataclass(frozen=True, slots=True)
class Outcome:
    """How an event type is counted."""

    metric: str
    decision: str


OUTCOMES: Final[Mapping[EventType, Outcome]] = MappingProxyType(
    {
        EventType.AUTHORIZATION_GRANTED: Outcome(
            semconv.AUTHORIZATION_DECISIONS, semconv.DECISION_ALLOW
        ),
        EventType.AUTHORIZATION_DENIED: Outcome(
            semconv.AUTHORIZATION_DECISIONS, semconv.DECISION_DENY
        ),
        # A rejected token is an authorization-path denial (no policy was reached).
        EventType.TOKEN_REJECTED: Outcome(semconv.AUTHORIZATION_DECISIONS, semconv.DECISION_DENY),
        EventType.TOKEN_ISSUED: Outcome(semconv.ISSUANCE_DECISIONS, semconv.DECISION_ALLOW),
        EventType.ISSUANCE_DENIED: Outcome(semconv.ISSUANCE_DECISIONS, semconv.DECISION_DENY),
        EventType.TOKEN_REPLACED: Outcome(semconv.REPLACEMENT_DECISIONS, semconv.DECISION_ALLOW),
        EventType.REPLACEMENT_DENIED: Outcome(semconv.REPLACEMENT_DECISIONS, semconv.DECISION_DENY),
    }
)


def looks_like_jose(value: str) -> bool:
    """Return True if ``value`` contains something shaped like a compact JWS or JWE."""
    return _JOSE_SHAPE.search(value) is not None


@dataclass(frozen=True, slots=True)
class EventAttributes:
    """Attributes for one audit event.

    Attributes:
        counter: Name of the counter this event increments.
        span: Every attribute, for the span event.
        metric: The bounded-cardinality subset (:data:`semconv.METRIC_ATTRIBUTES`).
        dropped: Names of attributes withheld because they looked like a token. A detail entry
            whose *key* looked like a token is reported as ``pytrat.detail.*`` so the name itself
            is safe to log.
    """

    counter: str
    span: Mapping[str, AttributeValue]
    metric: Mapping[str, AttributeValue]
    dropped: tuple[str, ...]


def event_attributes(event: AuditEvent) -> EventAttributes:
    """Map ``event`` to primitive OpenTelemetry attributes, withholding token-shaped strings.

    ``subject`` is deliberately not exported: it is usually a user identifier, and telemetry
    pipelines are rarely held to audit-log retention and access rules. Correlate by
    ``pytrat.transaction.id`` instead. ``trace_id`` and ``timestamp`` are carried by the span
    itself.

    Raises:
        KeyError: If ``event.event_type`` has no :data:`OUTCOMES` entry (a new event type that
            this package has not been updated for).
    """
    outcome = OUTCOMES[event.event_type]
    candidates: dict[str, str | int | None] = {
        semconv.AUDIT_SCHEMA_VERSION: SCHEMA_VERSION,
        semconv.EVENT_TYPE: event.event_type.value,
        semconv.DECISION: outcome.decision,
        semconv.REASON_CODE: event.reason_code.value if event.reason_code else None,
        semconv.SERVICE: event.service,
        semconv.TRANSACTION_ID: event.transaction_id,
        semconv.SCOPE: event.scope,
        semconv.POLICY_ID: event.policy_id,
        semconv.REQUESTING_WORKLOAD: event.requesting_workload,
        semconv.CALLER_WORKLOAD: event.caller_workload,
        semconv.TOKEN_DIGEST: event.token_digest,
    }
    agent = event.agent_context
    if agent is not None:
        candidates[semconv.AGENT_ORIGINATOR] = agent.originator
        candidates[semconv.AGENT_PROXIMATE] = agent.proximate
        candidates[semconv.AGENT_HOP_COUNT] = agent.hop_count
        candidates[semconv.AGENT_MIN_ASSURANCE_LEVEL] = agent.min_assurance_level

    attributes: dict[str, AttributeValue] = {}
    dropped: list[str] = []
    for name, value in candidates.items():
        if value is None:
            continue
        if isinstance(value, str) and looks_like_jose(value):
            dropped.append(name)
            continue
        attributes[name] = value
    for key, value in event.detail.items():
        name = semconv.DETAIL_PREFIX + key
        if looks_like_jose(name):
            dropped.append(_REDACTED_DETAIL_KEY)
        elif looks_like_jose(value):
            dropped.append(name)
        else:
            attributes[name] = value

    metric: dict[str, AttributeValue] = {
        name: attributes[name] for name in semconv.METRIC_ATTRIBUTES if name in attributes
    }
    return EventAttributes(
        counter=outcome.metric,
        span=MappingProxyType(attributes),
        metric=MappingProxyType(metric),
        dropped=tuple(dropped),
    )
