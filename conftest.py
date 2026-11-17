"""Repository-wide pytest configuration.

Every test in every package runs under :func:`_no_tokens_in_logs`, which fails the test if a
compact JWS appears in any log record (CLAUDE.md invariant 4; txn-tokens-11 §15.2).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator

import pytest

# Three base64url segments where the first two look like JSON objects ("eyJ" = '{"').
COMPACT_JWS = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}")


@pytest.fixture(autouse=True)
def _no_tokens_in_logs(caplog: pytest.LogCaptureFixture) -> Iterator[None]:
    caplog.set_level(logging.DEBUG)
    yield
    records = [r for when in ("setup", "call") for r in caplog.get_records(when)]
    leaked = [record for record in records if COMPACT_JWS.search(record.getMessage())]
    if leaked:
        pytest.fail(
            f"{len(leaked)} log record(s) contain a compact JWS (first from logger "
            f"{leaked[0].name!r}); tokens must never be logged",
            pytrace=False,
        )
