"""Multi-instance consistency against a real Redis.

Each "instance" is a separate RedisReplayStore with its own client and connection pool, as two
service processes would have. Skipped unless PYTRAT_TEST_REDIS_URL is set (except the Redis-down
test, which needs no server).
"""

from __future__ import annotations

import logging
import secrets
import socket
import threading
import time
from collections.abc import Iterator
from datetime import timedelta

import pytest
import redis

from _redis_testkit import real_redis_url
from pytrat.core import AuthorizationError, DependencyError, ReasonCode, replay_key
from pytrat.core.clock import SystemClock
from pytrat.redis import RedisReplayStore

pytestmark = pytest.mark.integration

INSTANCES = 4
THREADS = 32


@pytest.fixture
def prefix() -> Iterator[str]:
    """A fresh namespace per test; its keys are deleted afterwards."""
    url = real_redis_url()
    namespace = f"pytrat-test:{secrets.token_hex(8)}:"
    yield namespace
    admin = redis.Redis.from_url(url)
    try:
        for name in admin.scan_iter(match=f"{namespace}*"):
            admin.delete(name)
    finally:
        admin.close()


def instances(prefix: str, count: int, **options: object) -> list[RedisReplayStore]:
    url = real_redis_url()
    return [
        RedisReplayStore.from_url(url, prefix=prefix, **options)  # type: ignore[arg-type]
        for _ in range(count)
    ]


def race(stores: list[RedisReplayStore], key: str, expires_at: float) -> list[str]:
    barrier = threading.Barrier(THREADS)
    outcomes: list[str] = []
    lock = threading.Lock()

    def attempt(index: int) -> None:
        barrier.wait()
        try:
            stores[index % len(stores)].record_once(key, expires_at)
            outcome = "OK"
        except AuthorizationError as exc:
            outcome = exc.reason.value
        except DependencyError as exc:
            outcome = f"DEPENDENCY:{exc.detail}"
        with lock:
            outcomes.append(outcome)

    threads = [threading.Thread(target=attempt, args=(i,)) for i in range(THREADS)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return outcomes


def test_concurrent_first_use_across_instances_has_exactly_one_winner(prefix) -> None:
    stores = instances(prefix, INSTANCES)
    for round_ in range(20):
        key = replay_key(f"txn-race-{round_}", "payments.transfer")
        outcomes = race(stores, key, time.time() + 60)
        assert outcomes.count("OK") == 1, outcomes
        assert outcomes.count("REPLAY_DETECTED") == THREADS - 1, outcomes


def test_replay_on_a_second_instance_is_rejected(prefix) -> None:
    first, second = instances(prefix, 2)
    key = replay_key("txn-9274", "payments.transfer")
    first.record_once(key, time.time() + 60)
    with pytest.raises(AuthorizationError) as caught:
        second.record_once(key, time.time() + 60)
    assert caught.value.reason is ReasonCode.REPLAY_DETECTED


def test_raw_txn_is_not_stored_and_ttl_is_bounded(prefix) -> None:
    (store,) = instances(prefix, 1, retention_margin=timedelta(seconds=5))
    store.record_once(replay_key("txn-secret-value", "op"), time.time() + 30)
    admin = redis.Redis.from_url(real_redis_url())
    try:
        names = list(admin.scan_iter(match=f"{prefix}*"))
        assert len(names) == 1
        assert b"txn-secret-value" not in names[0]
        assert 30_000 <= admin.pttl(names[0]) <= 35_000
    finally:
        admin.close()


def test_record_expires_and_the_key_can_be_used_again(prefix) -> None:
    store, other = instances(prefix, 2, retention_margin=timedelta(0), clock=SystemClock())
    key = replay_key("txn-expiring", "op")
    store.record_once(key, time.time() + 0.2)
    with pytest.raises(AuthorizationError):
        other.record_once(key, time.time() + 0.2)
    deadline = time.monotonic() + 5
    while True:
        try:
            other.record_once(key, time.time() + 60)
            break
        except AuthorizationError:
            assert time.monotonic() < deadline, "record did not expire"
            time.sleep(0.05)


def _closed_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def test_redis_down_denies_with_dependency_error(caplog: pytest.LogCaptureFixture) -> None:
    url = f"redis://:hunter2@127.0.0.1:{_closed_port()}/0"
    store = RedisReplayStore.from_url(url, socket_timeout=0.2)
    started = time.monotonic()
    with pytest.raises(DependencyError) as caught:
        store.record_once(replay_key("txn-down", "op"), time.time() + 60)
    assert time.monotonic() - started < 2
    assert caught.value.reason is ReasonCode.DEPENDENCY_UNAVAILABLE
    logged = " ".join(record.getMessage() for record in caplog.records)
    assert "hunter2" not in logged
    assert "txn-down" not in logged
    assert all(record.levelno <= logging.WARNING for record in caplog.records)
