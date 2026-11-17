"""In-process stand-in for one Redis server, plus the env switch for real-Redis tests."""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field

import pytest

from pytrat.core.clock import FrozenClock

REDIS_URL_ENV = "PYTRAT_TEST_REDIS_URL"


def real_redis_url() -> str:
    url = os.environ.get(REDIS_URL_ENV)
    if not url:
        pytest.skip(f"set {REDIS_URL_ENV} to run tests against a real Redis")
    return url


@dataclass
class FakeRedisServer:
    """Shared keyspace with Redis's SET NX PX semantics, on an injected clock."""

    clock: FrozenClock
    entries: dict[str, tuple[str, float]] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def set_nx_px(self, name: str, value: str, px: int) -> bool | None:
        if px <= 0:
            raise AssertionError("Redis rejects non-positive PX")
        now = self.clock.now()
        with self.lock:
            existing = self.entries.get(name)
            if existing is not None and existing[1] > now:
                return None
            self.entries[name] = (value, now + px / 1000)
            return True


@dataclass
class FakeRedisClient:
    """One connection to a :class:`FakeRedisServer`; records every call."""

    server: FakeRedisServer
    calls: list[tuple[str, str, bool, int]] = field(default_factory=list)
    error: BaseException | None = None
    reply: object = "server"

    def set(self, name: str, value: str, *, nx: bool, px: int) -> object:
        self.calls.append((name, value, nx, px))
        if self.error is not None:
            raise self.error
        if self.reply != "server":
            return self.reply
        assert nx is True
        return self.server.set_nx_px(name, value, px)
