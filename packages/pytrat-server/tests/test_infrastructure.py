"""Issuance log, rate limiter, ids and the command-line entry point."""

from __future__ import annotations

import sqlite3
import uuid
from contextlib import closing
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from pytrat.core import AuditEvent, DependencyError, EventType, FrozenClock, MemorySink, ReasonCode
from pytrat.server import (
    AuditIntegrityError,
    AuditRecorder,
    InMemoryIssuanceLog,
    OAuthError,
    SqliteIssuanceLog,
    TokenBucketRateLimiter,
    new_txn_id,
)
from pytrat.server import ids as ids_module
from pytrat.server.ids import uuid7_from


def event(event_type=EventType.TOKEN_ISSUED, txn="txn-1", **fields):
    return AuditEvent(
        event_type=event_type,
        service="test",
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        transaction_id=txn,
        trace_id=None,
        **fields,
    )


@pytest.fixture
async def sqlite_log(tmp_path):
    log = SqliteIssuanceLog(tmp_path / "audit.db")
    yield log
    await log.close()


async def test_sqlite_log_chain_and_counts(sqlite_log):
    first = await sqlite_log.append(event(), "d1")
    second = await sqlite_log.append(event(EventType.TOKEN_REPLACED), "d2")
    await sqlite_log.append(event(EventType.TOKEN_REPLACED, txn="other"), "d3")
    await sqlite_log.append(event(EventType.ISSUANCE_DENIED, txn=None), None)
    assert second.prev_hash == first.row_hash
    assert first.prev_hash == "0" * 64
    assert [r.seq for r in await sqlite_log.chain("txn-1")] == [1, 2]
    assert await sqlite_log.replacement_count("txn-1") == 1
    assert await sqlite_log.replacement_count("none") == 0
    assert await sqlite_log.verify_integrity() == 4


async def test_sqlite_log_is_append_only(sqlite_log, tmp_path):
    await sqlite_log.append(event(), "d1")
    with closing(sqlite3.connect(tmp_path / "audit.db")) as raw:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            raw.execute("UPDATE issuance_log SET record = 'x'")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            raw.execute("DELETE FROM issuance_log")


async def test_audit_hash_chain_tamper_detection(sqlite_log, tmp_path):
    """Attack: an insider with database access rewrites a record."""
    for _ in range(3):
        await sqlite_log.append(event(), "d")
    raw = sqlite3.connect(tmp_path / "audit.db")
    try:
        raw.execute("DROP TRIGGER issuance_log_no_update")
        raw.execute(
            "UPDATE issuance_log SET record = replace(record, 'txn-1', 'txn-X') WHERE seq = 2"
        )
        raw.commit()
    finally:
        raw.close()
    with pytest.raises(AuditIntegrityError, match="row 2"):
        await sqlite_log.verify_integrity()


async def test_audit_chain_detects_deleted_row(tmp_path):
    log = SqliteIssuanceLog(tmp_path / "a.db")
    try:
        for _ in range(3):
            await log.append(event(), "d")
        raw = sqlite3.connect(tmp_path / "a.db")
        raw.execute("DROP TRIGGER issuance_log_no_delete")
        raw.execute("DELETE FROM issuance_log WHERE seq = 2")
        raw.commit()
        raw.close()
        with pytest.raises(AuditIntegrityError, match="row 3"):
            await log.verify_integrity()
    finally:
        await log.close()


async def test_sqlite_log_unavailable_is_dependency_error(tmp_path):
    log = SqliteIssuanceLog(tmp_path / "missing-dir" / "audit.db")
    with pytest.raises(DependencyError):
        await log.append(event(), "d")
    with pytest.raises(DependencyError):
        await log.chain("t")
    with pytest.raises(DependencyError):
        await log.replacement_count("t")
    await log.close()


async def test_sqlite_schema_failure_closes_connection(tmp_path):
    path = tmp_path / "audit.db"
    with closing(sqlite3.connect(path)) as raw:
        raw.execute("CREATE VIEW issuance_log AS SELECT 1")
        raw.commit()
    log = SqliteIssuanceLog(path)
    with pytest.raises(DependencyError):
        await log.append(event(), "d")
    await log.close()


async def test_memory_log_matches_contract():
    log = InMemoryIssuanceLog()
    await log.append(event(), "a")
    await log.append(event(EventType.TOKEN_REPLACED), "b")
    assert await log.replacement_count("txn-1") == 1
    assert len(await log.chain("txn-1")) == 2
    assert await log.verify_integrity() == 2
    log.records[0] = replace(log.records[0], record="{}")
    with pytest.raises(AuditIntegrityError):
        await log.verify_integrity()


async def test_recorder_fans_out_and_survives_log_failure_on_denial(caplog):
    class BrokenLog:
        async def append(self, event, claims_digest):
            raise DependencyError("down")

    sink = MemorySink()
    recorder = AuditRecorder(BrokenLog(), sink)
    await recorder.record_denial(event(EventType.ISSUANCE_DENIED))
    assert len(sink.events) == 1
    assert "DEPENDENCY_UNAVAILABLE" in caplog.text
    with pytest.raises(DependencyError):
        await recorder.record_success(event(), "d")


async def test_recorder_survives_a_raising_sink_on_denial(caplog):
    """Regression (found by tests/integration/test_failure_injection.py): a sink that raised
    from ``emit`` escaped ``record_denial`` ("never raises") and replaced the denial with a 500.
    """

    class RaisingSink:
        def emit(self, event):
            raise OSError("audit volume is full")

    log = InMemoryIssuanceLog()
    recorder = AuditRecorder(log, RaisingSink())
    await recorder.record_denial(event(EventType.ISSUANCE_DENIED))
    assert [record.event_type for record in log.records] == [EventType.ISSUANCE_DENIED.value]
    assert "audit sink could not record a denial: OSError" in caplog.text
    with pytest.raises(OSError, match="full"):
        await recorder.record_success(event(), "d")  # success still fails closed


def test_token_bucket():
    clock = FrozenClock(0.0)
    limiter = TokenBucketRateLimiter(rate=1.0, burst=2, clock=clock, max_keys=2)
    limiter.acquire("a")
    limiter.acquire("a")
    with pytest.raises(OAuthError) as info:
        limiter.acquire("a")
    assert (info.value.status, info.value.error, info.value.reason) == (
        429,
        "slow_down",
        ReasonCode.RATE_LIMITED,
    )
    clock.advance(1.0)
    limiter.acquire("a")
    limiter.acquire("b")
    with pytest.raises(OAuthError):
        limiter.acquire("c")  # bounded: refuses rather than evicting
    with pytest.raises(ValueError, match="rate"):
        TokenBucketRateLimiter(rate=0, burst=1, clock=clock)


def test_uuid7_layout_rfc_9562():
    value = uuid7_from(0x0123456789AB, bytes(range(10)))
    assert value.version == 7
    assert value.variant == uuid.RFC_4122
    assert value.int >> 80 == 0x0123456789AB
    with pytest.raises(ValueError, match="48 bits"):
        uuid7_from(1 << 48, bytes(10))
    with pytest.raises(ValueError, match="10 bytes"):
        uuid7_from(0, bytes(9))


def test_new_txn_id_with_stdlib(monkeypatch):
    calls = []

    def fake_uuid7():
        calls.append(1)
        return uuid7_from(1, bytes(10))

    monkeypatch.setattr(uuid, "uuid7", fake_uuid7, raising=False)
    assert uuid.UUID(new_txn_id()).version == 7
    assert calls == [1]


def test_new_txn_id_local_fallback(monkeypatch):
    monkeypatch.delattr(uuid, "uuid7", raising=False)
    assert ids_module._stdlib_uuid7() is None
    first, second = uuid.UUID(new_txn_id()), uuid.UUID(new_txn_id())
    assert first.version == second.version == 7
    assert first != second


def test_new_txn_id_with_injected_clock_is_time_ordered():
    clock = FrozenClock(1_795_000_000.0)
    earlier = uuid.UUID(new_txn_id(clock))
    clock.advance(1)
    later = uuid.UUID(new_txn_id(clock))
    assert earlier.int >> 80 == 1_795_000_000_000
    assert later > earlier


def test_main_runs_uvicorn(monkeypatch, config, tmp_path):
    import yaml

    from pytrat.server import __main__ as entry

    path = tmp_path / "tts.yaml"
    path.write_text(yaml.safe_dump(config))
    calls = []
    monkeypatch.setattr(entry.uvicorn, "run", lambda app, **kw: calls.append(kw))
    entry.main(["--config", str(path), "--port", "9999"])
    assert calls == [{"host": "127.0.0.1", "port": 9999, "server_header": False}]
