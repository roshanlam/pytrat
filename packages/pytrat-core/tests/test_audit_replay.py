from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

import pytest

from pytrat.core import (
    AuditEvent,
    AuthorizationError,
    DependencyError,
    EventType,
    InMemoryReplayStore,
    JsonLinesSink,
    LoggingSink,
    MemorySink,
    NullSink,
    ReasonCode,
    parse_claims,
    replay_key,
)
from pytrat.core.audit import AgentAuditContext, current_trace_id
from pytrat.core.clock import FrozenClock

CLAIMS = parse_claims(
    {
        "aud": "payments.internal",
        "txn": "txn-9274",
        "sub": "user:123",
        "scope": "payments.transfer",
        "req_wl": "api-gateway",
        "iat": 1,
        "exp": 2,
        "tctx": {"amount_minor": 10000},
        "agentic_ctx": {
            "originator": {"id": "external-agent", "session_id": "secret-session"},
            "proximate_agent": {"id": "payment-agent"},
            "chain_metadata": {"hop_count": 2, "min_assurance_level": "low"},
        },
    }
)


class TestAuditEvent:
    def test_for_claims_serialises_schema(self) -> None:
        event = AuditEvent.for_claims(
            EventType.AUTHORIZATION_DENIED,
            service="ledger-service",
            claims=CLAIMS,
            token_digest="abc",
            policy_id="transfer-execution",
            reason_code=ReasonCode.TRANSACTION_CONTEXT_MISMATCH,
            detail={"field": "amount_minor"},
            timestamp=datetime(2026, 11, 17, 12, tzinfo=UTC),
        )
        data = json.loads(event.to_json())
        assert data == {
            "schema_version": 1,
            "event_type": "authorization.denied",
            "timestamp": "2026-11-17T12:00:00Z",
            "service": "ledger-service",
            "transaction_id": "txn-9274",
            "subject": "user:123",
            "scope": "payments.transfer",
            "policy_id": "transfer-execution",
            "reason_code": "TRANSACTION_CONTEXT_MISMATCH",
            "requesting_workload": "api-gateway",
            "token_digest": "abc",
            "agent_context": {
                "originator": "external-agent",
                "proximate": "payment-agent",
                "hop_count": 2,
                "min_assurance_level": "low",
            },
            "detail": {"field": "amount_minor"},
        }

    def test_never_contains_context_values_or_session_ids(self) -> None:
        rendered = AuditEvent.for_claims(
            EventType.AUTHORIZATION_GRANTED, service="s", claims=CLAIMS
        ).to_json()
        assert "10000" not in rendered
        assert "secret-session" not in rendered

    def test_minimal_event(self) -> None:
        data = AuditEvent.for_claims(EventType.TOKEN_REJECTED, service="s", claims=None).to_dict()
        assert set(data) == {"schema_version", "event_type", "timestamp", "service"}

    def test_agent_context_absent_without_agentic_ctx(self) -> None:
        plain = parse_claims({**CLAIMS.to_payload(), "agentic_ctx": None})
        assert AgentAuditContext.from_claims(plain) is None
        assert "agent_context" not in AuditEvent(EventType.TOKEN_ISSUED, service="s").to_dict()
        no_level = AgentAuditContext("o", "p", 1)
        event = AuditEvent(EventType.TOKEN_ISSUED, service="s", agent_context=no_level)
        assert "min_assurance_level" not in event.to_dict()["agent_context"]  # type: ignore[operator]

    def test_trace_id_absent_without_opentelemetry(self) -> None:
        assert current_trace_id() is None


class TestSinks:
    def test_memory_and_null(self) -> None:
        sink = MemorySink()
        sink.emit(AuditEvent(EventType.TOKEN_ISSUED, service="s"))
        sink.emit(AuditEvent(EventType.TOKEN_REPLACED, service="s"))
        assert [e.event_type for e in sink.of_type(EventType.TOKEN_ISSUED)] == [
            EventType.TOKEN_ISSUED
        ]
        NullSink().emit(AuditEvent(EventType.TOKEN_ISSUED, service="s"))

    def test_logging_sink(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.INFO, logger="pytrat.audit"):
            LoggingSink().emit(AuditEvent(EventType.TOKEN_ISSUED, service="svc"))
        assert '"service":"svc"' in caplog.text

    def test_logging_sink_never_raises(self, caplog: pytest.LogCaptureFixture) -> None:
        class Broken(logging.Logger):
            def log(self, *args, **kwargs):  # type: ignore[override]
                raise RuntimeError("boom")

        LoggingSink(Broken("x")).emit(AuditEvent(EventType.TOKEN_ISSUED, service="s"))
        assert "audit logging failed" in caplog.text

    def test_json_lines_sink_writes_and_flushes(self, tmp_path) -> None:
        path = tmp_path / "audit" / "events.jsonl"
        sink = JsonLinesSink(path)
        for _ in range(3):
            sink.emit(AuditEvent(EventType.TOKEN_ISSUED, service="s"))
        sink.close()
        lines = path.read_text().splitlines()
        assert len(lines) == 3
        assert all(json.loads(line)["event_type"] == "token.issued" for line in lines)

    def test_json_lines_sink_drops_when_full(
        self, tmp_path, caplog: pytest.LogCaptureFixture
    ) -> None:
        sink = JsonLinesSink(tmp_path / "e.jsonl", max_queue=1)
        sink._queue.put(None)  # stop the writer so the queue stays full
        sink._thread.join()
        sink._queue.put(AuditEvent(EventType.TOKEN_ISSUED, service="s"))
        for _ in range(3):
            sink.emit(AuditEvent(EventType.TOKEN_ISSUED, service="s"))
        assert sink.dropped == 3
        assert caplog.text.count("audit queue full") == 1


class TestReplay:
    def test_second_use_within_lifetime_is_rejected(self) -> None:
        clock = FrozenClock(1000)
        store = InMemoryReplayStore(clock=clock)
        key = replay_key("txn-1", "transfer")
        store.record_once(key, expires_at=1060)
        with pytest.raises(AuthorizationError) as excinfo:
            store.record_once(key, expires_at=1060)
        assert excinfo.value.reason is ReasonCode.REPLAY_DETECTED
        store.record_once(replay_key("txn-1", "other-op"), expires_at=1060)

    def test_entries_expire(self) -> None:
        clock = FrozenClock(1000)
        store = InMemoryReplayStore(clock=clock)
        store.record_once("k", expires_at=1010)
        clock.advance(11)
        store.record_once("k", expires_at=1100)
        assert len(store) == 1

    def test_full_store_fails_closed(self) -> None:
        store = InMemoryReplayStore(max_entries=1, clock=FrozenClock(0))
        store.record_once("a", expires_at=100)
        with pytest.raises(DependencyError):
            store.record_once("b", expires_at=100)

    def test_keys_are_unambiguous(self) -> None:
        assert replay_key("a|b", "c") != replay_key("a", "b|c")
