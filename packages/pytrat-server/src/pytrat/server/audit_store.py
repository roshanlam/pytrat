"""The TTS issuance log: an append-only, hash-chained record of every issuance decision.

PyTraT profile P9 / txn-tokens-11 §13.15: the call chain of a transaction is maintained by the TTS
outside the token. Every issuance, replacement and denial is appended here, keyed by ``txn``.
Records hold audit events and a SHA-256 digest of the signed claims; never tokens
(txn-tokens-11 §15.2).

Tamper evidence: each row stores ``prev_hash`` and
``row_hash = SHA-256(prev_hash || canonical JSON of the record)``. :meth:`verify_integrity`
recomputes the chain. SQLite triggers additionally refuse ``UPDATE`` and ``DELETE``.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol

import aiosqlite

from pytrat.core.audit import AuditEvent, AuditSink, EventType
from pytrat.core.errors import DependencyError, PyTraTError, ReasonCode

__all__ = [
    "GENESIS_HASH",
    "AuditIntegrityError",
    "AuditRecorder",
    "InMemoryIssuanceLog",
    "IssuanceLog",
    "IssuanceRecord",
    "SqliteIssuanceLog",
]

_logger = logging.getLogger(__name__)

GENESIS_HASH: Final = "0" * 64

_SCHEMA: Final = (
    """
    CREATE TABLE IF NOT EXISTS issuance_log (
        seq        INTEGER PRIMARY KEY AUTOINCREMENT,
        txn        TEXT,
        event_type TEXT NOT NULL,
        record     TEXT NOT NULL,
        prev_hash  TEXT NOT NULL,
        row_hash   TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS issuance_log_txn ON issuance_log (txn)",
    """
    CREATE TRIGGER IF NOT EXISTS issuance_log_no_update BEFORE UPDATE ON issuance_log
    BEGIN SELECT RAISE(ABORT, 'issuance_log is append-only'); END
    """,
    """
    CREATE TRIGGER IF NOT EXISTS issuance_log_no_delete BEFORE DELETE ON issuance_log
    BEGIN SELECT RAISE(ABORT, 'issuance_log is append-only'); END
    """,
)
_COLUMNS: Final = "seq, txn, event_type, record, prev_hash, row_hash"


class AuditIntegrityError(PyTraTError):
    """The issuance log's hash chain does not verify."""

    def __init__(self, detail: str) -> None:
        super().__init__(ReasonCode.DEPENDENCY_UNAVAILABLE, detail)


@dataclass(frozen=True, slots=True)
class IssuanceRecord:
    """One row of the issuance log.

    Attributes:
        seq: Position in the log, starting at 1.
        txn: Transaction identifier, if the event has one.
        event_type: The audit event type.
        record: Canonical JSON of ``{"event": ..., "claims_digest": ...}``.
        prev_hash: ``row_hash`` of the previous row (or :data:`GENESIS_HASH`).
        row_hash: SHA-256 over ``prev_hash`` and ``record``.
    """

    seq: int
    txn: str | None
    event_type: str
    record: str
    prev_hash: str
    row_hash: str


def canonical_record(event: AuditEvent, claims_digest: str | None) -> str:
    """Canonical JSON for one log entry: sorted keys, no whitespace."""
    body = {"event": event.to_dict(), "claims_digest": claims_digest}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def chain_hash(prev_hash: str, record: str) -> str:
    """``SHA-256(prev_hash || record)`` as hex."""
    return hashlib.sha256(f"{prev_hash}{record}".encode()).hexdigest()


def verify_chain(records: Sequence[IssuanceRecord]) -> int:
    """Recompute a full hash chain in ``seq`` order.

    Returns:
        The number of verified rows.

    Raises:
        AuditIntegrityError: Naming the first row that does not verify.
    """
    prev_hash = GENESIS_HASH
    for record in records:
        if record.prev_hash != prev_hash or record.row_hash != chain_hash(prev_hash, record.record):
            raise AuditIntegrityError(f"issuance log row {record.seq} does not verify")
        prev_hash = record.row_hash
    return len(records)


class IssuanceLog(Protocol):
    """Append-only storage for issuance events, queryable by ``txn``."""

    async def append(self, event: AuditEvent, claims_digest: str | None) -> IssuanceRecord:
        """Append ``event``.

        Raises:
            DependencyError: If the log cannot record it (the caller must deny).
        """
        ...

    async def chain(self, txn: str) -> list[IssuanceRecord]:
        """Return every record of ``txn`` in log order."""
        ...

    async def replacement_count(self, txn: str) -> int:
        """Return how many replacements were issued for ``txn``."""
        ...


class InMemoryIssuanceLog:
    """A hash-chained log held in memory. For tests and development."""

    __slots__ = ("_lock", "records")

    def __init__(self) -> None:
        self.records: list[IssuanceRecord] = []
        self._lock = asyncio.Lock()

    async def append(self, event: AuditEvent, claims_digest: str | None) -> IssuanceRecord:
        """Append ``event``; see :class:`IssuanceLog`."""
        async with self._lock:
            prev_hash = self.records[-1].row_hash if self.records else GENESIS_HASH
            record_json = canonical_record(event, claims_digest)
            record = IssuanceRecord(
                seq=len(self.records) + 1,
                txn=event.transaction_id,
                event_type=event.event_type.value,
                record=record_json,
                prev_hash=prev_hash,
                row_hash=chain_hash(prev_hash, record_json),
            )
            self.records.append(record)
            return record

    async def chain(self, txn: str) -> list[IssuanceRecord]:
        """Return every record of ``txn``; see :class:`IssuanceLog`."""
        return [record for record in self.records if record.txn == txn]

    async def replacement_count(self, txn: str) -> int:
        """Count replacements of ``txn``; see :class:`IssuanceLog`."""
        replaced = EventType.TOKEN_REPLACED.value
        return sum(1 for r in self.records if r.txn == txn and r.event_type == replaced)

    async def verify_integrity(self) -> int:
        """Recompute the chain; see :func:`verify_chain`."""
        return verify_chain(self.records)


class SqliteIssuanceLog:
    """A hash-chained log in SQLite via :mod:`aiosqlite`.

    The connection opens lazily on first use, inside the running event loop. Appends are
    serialised by a lock so the chain is linear. Call :meth:`close` on shutdown.
    """

    __slots__ = ("_connection", "_lock", "_path")

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._connection: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()

    async def _connect(self) -> aiosqlite.Connection:
        if self._connection is None:
            connection = await aiosqlite.connect(self._path)
            try:
                for statement in _SCHEMA:
                    await connection.execute(statement)
                await connection.commit()
            except sqlite3.Error:
                await connection.close()
                raise
            self._connection = connection
        return self._connection

    async def append(self, event: AuditEvent, claims_digest: str | None) -> IssuanceRecord:
        """Append ``event``; see :class:`IssuanceLog`."""
        record_json = canonical_record(event, claims_digest)
        try:
            async with self._lock:
                connection = await self._connect()
                async with connection.execute(
                    "SELECT row_hash FROM issuance_log ORDER BY seq DESC LIMIT 1"
                ) as cursor:
                    last = await cursor.fetchone()
                prev_hash = str(last[0]) if last is not None else GENESIS_HASH
                row_hash = chain_hash(prev_hash, record_json)
                cursor = await connection.execute(
                    "INSERT INTO issuance_log (txn, event_type, record, prev_hash, row_hash)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (
                        event.transaction_id,
                        event.event_type.value,
                        record_json,
                        prev_hash,
                        row_hash,
                    ),
                )
                seq = cursor.lastrowid
                await cursor.close()
                await connection.commit()
        except sqlite3.Error:
            raise DependencyError("issuance log is unavailable") from None
        return IssuanceRecord(
            seq=int(seq or 0),
            txn=event.transaction_id,
            event_type=event.event_type.value,
            record=record_json,
            prev_hash=prev_hash,
            row_hash=row_hash,
        )

    async def _select(self, sql: str, parameters: tuple[object, ...] = ()) -> list[IssuanceRecord]:
        try:
            connection = await self._connect()
            async with connection.execute(sql, parameters) as cursor:
                rows = await cursor.fetchall()
        except sqlite3.Error:
            raise DependencyError("issuance log is unavailable") from None
        return [
            IssuanceRecord(
                seq=int(row[0]),
                txn=None if row[1] is None else str(row[1]),
                event_type=str(row[2]),
                record=str(row[3]),
                prev_hash=str(row[4]),
                row_hash=str(row[5]),
            )
            for row in rows
        ]

    async def chain(self, txn: str) -> list[IssuanceRecord]:
        """Return every record of ``txn``; see :class:`IssuanceLog`."""
        return await self._select(
            f"SELECT {_COLUMNS} FROM issuance_log WHERE txn = ? ORDER BY seq",  # noqa: S608
            (txn,),
        )

    async def replacement_count(self, txn: str) -> int:
        """Count replacements of ``txn``; see :class:`IssuanceLog`."""
        try:
            connection = await self._connect()
            async with connection.execute(
                "SELECT COUNT(*) FROM issuance_log WHERE txn = ? AND event_type = ?",
                (txn, EventType.TOKEN_REPLACED.value),
            ) as cursor:
                row = await cursor.fetchone()
        except sqlite3.Error:
            raise DependencyError("issuance log is unavailable") from None
        return int(row[0]) if row is not None else 0

    async def verify_integrity(self) -> int:
        """Recompute the whole chain.

        Returns:
            The number of verified rows.

        Raises:
            AuditIntegrityError: If any row was altered, removed or inserted out of chain.
        """
        records = await self._select(f"SELECT {_COLUMNS} FROM issuance_log ORDER BY seq")  # noqa: S608
        return verify_chain(records)

    async def close(self) -> None:
        """Close the connection."""
        if self._connection is not None:
            await self._connection.close()
            self._connection = None


class AuditRecorder:
    """Writes each event to the issuance log, then fans it out to an :class:`AuditSink`."""

    __slots__ = ("_log", "_sink")

    def __init__(self, log: IssuanceLog, sink: AuditSink) -> None:
        self._log = log
        self._sink = sink

    async def record_success(self, event: AuditEvent, claims_digest: str) -> None:
        """Record an issuance or replacement. The token must not be returned unless this succeeds.

        The issuance log is authoritative (PyTraT profile P9). Once it has recorded the event,
        a failing secondary sink is logged and ignored: withholding the token then would leave
        a logged issuance that never happened, and would consume the replacement budget.

        Raises:
            DependencyError: If the issuance log cannot record the event (fail closed: the
                call chain would otherwise be lost, PyTraT profile P9).
        """
        await self._log.append(event, claims_digest)
        self._emit(event)

    def _emit(self, event: AuditEvent) -> None:
        try:
            self._sink.emit(event)
        except Exception as exc:  # noqa: BLE001 - the authoritative log already holds the event; a sink breaking its no-raise contract must not change the outcome
            _logger.error("audit sink could not record an event: %s", type(exc).__name__)  # noqa: TRY400 - the exception text may echo event data

    async def record_denial(self, event: AuditEvent) -> None:
        """Record a denial. Never raises: the request is already being refused."""
        try:
            await self._log.append(event, None)
        except PyTraTError as exc:
            _logger.error(  # noqa: TRY400 - a traceback adds nothing; reason code only
                "issuance log could not record a denial: %s", exc.reason.value
            )
        self._emit(event)
