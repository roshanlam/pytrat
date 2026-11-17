"""txn-tokens-11 §15.2 / CLAUDE.md invariant 4: tokens never reach logs or audit records."""

from __future__ import annotations

import logging
import re
import sqlite3
from contextlib import closing

from pytrat.core import MemorySink
from pytrat.core.constants import TOKEN_TYPE_REFRESH_TOKEN
from pytrat.server import build_components, create_app, parse_settings

COMPACT_JWS = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


async def test_no_compact_jws_in_logs_or_audit(make_tts, config, tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    config["audit_db_path"] = "audit.db"
    settings = parse_settings(config, tmp_path)
    sink = MemorySink()
    tts = make_tts()
    components = build_components(settings, clock=tts.clock, sink=sink)
    tts.app, tts.components, tts.sink = create_app(components), components, sink
    try:
        subject = tts.access_token()
        token = await tts.issue(
            subject_token=subject,
            scope="payments.transfer payments.read",
            # A hostile requester tries to smuggle tokens into audited key names and values.
            request_details={subject: 1, "currency": "USD"},
            request_context={"x": subject},
        )
        replaced = await tts.post(tts.replacement_form(token, scope="payments.read"))
        assert replaced.status_code == 200
        form = tts.form(subject_token=subject)
        await tts.post(form)
        await tts.post(form)  # replayed assertion
        await tts.post(tts.form(subject_token=subject[:-3] + "abc"))
        await tts.post(tts.form(subject_token_type=TOKEN_TYPE_REFRESH_TOKEN))
        await tts.post(tts.form(scope="ledger.write"))
        await tts.post(tts.replacement_form(token, scope="ledger.write"))
        tts.clock.advance(120)
        await tts.post(tts.replacement_form(token))
    finally:
        for callback in components.on_shutdown:
            await callback()

    with closing(sqlite3.connect(tmp_path / "audit.db")) as raw:
        rows = raw.execute("SELECT record FROM issuance_log").fetchall()
    assert len(rows) >= 9
    texts = {
        "logs": caplog.text,
        "log messages": "\n".join(r.getMessage() for r in caplog.records),
        "sink": "\n".join(event.to_json() for event in sink.events),
        "issuance log": "\n".join(row[0] for row in rows),
        "reprs": repr(sink.events),
    }
    for where, text in texts.items():
        assert not COMPACT_JWS.search(text), f"compact JWS found in {where}"
        assert subject not in text
        assert token not in text
