"""RedisReplayStore against an in-process fake: every decision and every failure path."""

from __future__ import annotations

import hashlib
import logging
import math
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import ResponseError
from redis.exceptions import TimeoutError as RedisTimeoutError

from _redis_testkit import FakeRedisClient, FakeRedisServer
from pytrat.core import (
    AuthorizationError,
    ConfigurationError,
    DependencyError,
    ReasonCode,
    ReplayStore,
    replay_key,
)
from pytrat.core.clock import FrozenClock
from pytrat.redis import DEFAULT_PREFIX, RedisReplayStore

NOW = 1_795_000_000.0
KEY = replay_key("txn-9274", "payments.transfer")


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock(NOW)


@pytest.fixture
def server(clock: FrozenClock) -> FakeRedisServer:
    return FakeRedisServer(clock=clock)


@pytest.fixture
def client(server: FakeRedisServer) -> FakeRedisClient:
    return FakeRedisClient(server)


def make_store(client: FakeRedisClient, clock: FrozenClock, **options: object) -> RedisReplayStore:
    return RedisReplayStore(client, clock=clock, **options)  # type: ignore[arg-type]


# ------------------------------------------------------------------ decisions


def test_satisfies_the_core_replay_store_protocol(client, clock) -> None:
    store: ReplayStore = make_store(client, clock)
    store.record_once(KEY, NOW + 60)


def test_first_use_is_recorded_with_one_atomic_set_nx(client, clock) -> None:
    make_store(client, clock).record_once(KEY, NOW + 60)
    assert len(client.calls) == 1
    _, value, nx, _ = client.calls[0]
    assert nx is True
    assert value == "1"


def test_second_use_is_rejected_as_replay(client, clock) -> None:
    store = make_store(client, clock)
    store.record_once(KEY, NOW + 60)
    with pytest.raises(AuthorizationError) as caught:
        store.record_once(KEY, NOW + 60)
    assert caught.value.reason is ReasonCode.REPLAY_DETECTED


def test_replay_on_another_instance_is_rejected(server, clock) -> None:
    first = make_store(FakeRedisClient(server), clock)
    second = make_store(FakeRedisClient(server), clock)
    first.record_once(KEY, NOW + 60)
    with pytest.raises(AuthorizationError) as caught:
        second.record_once(KEY, NOW + 60)
    assert caught.value.reason is ReasonCode.REPLAY_DETECTED


def test_concurrent_uses_across_instances_have_exactly_one_winner(server, clock) -> None:
    stores = [make_store(FakeRedisClient(server), clock) for _ in range(2)]

    def attempt(index: int) -> str:
        try:
            stores[index % 2].record_once(KEY, NOW + 60)
        except AuthorizationError as exc:
            return exc.reason.value
        return "OK"

    with ThreadPoolExecutor(max_workers=16) as pool:
        outcomes = list(pool.map(attempt, range(64)))
    assert outcomes.count("OK") == 1
    assert outcomes.count("REPLAY_DETECTED") == 63


def test_distinct_keys_are_independent(client, clock) -> None:
    store = make_store(client, clock)
    store.record_once(replay_key("txn-1", "op"), NOW + 60)
    store.record_once(replay_key("txn-2", "op"), NOW + 60)
    store.record_once(replay_key("txn-1", "other-op"), NOW + 60)


def test_prefixes_isolate_namespaces(server, clock) -> None:
    make_store(FakeRedisClient(server), clock, prefix="ledger:").record_once(KEY, NOW + 60)
    make_store(FakeRedisClient(server), clock, prefix="payments:").record_once(KEY, NOW + 60)


# ------------------------------------------------------------------ key handling


def test_raw_txn_is_never_sent_to_redis(client, clock) -> None:
    make_store(client, clock).record_once(KEY, NOW + 60)
    name = client.calls[0][0]
    assert "txn-9274" not in name
    assert name == DEFAULT_PREFIX + hashlib.sha256(KEY.encode()).hexdigest()


def test_key_with_lone_surrogate_is_hashed_not_crashed(client, clock) -> None:
    store = make_store(client, clock)
    store.record_once(replay_key("txn-\ud800", "op"), NOW + 60)
    with pytest.raises(AuthorizationError) as caught:
        store.record_once(replay_key("txn-\ud800", "op"), NOW + 60)
    assert caught.value.reason is ReasonCode.REPLAY_DETECTED
    store.record_once(replay_key("txn-\ud801", "op"), NOW + 60)


# ------------------------------------------------------------------ expiry


def test_ttl_is_relative_to_the_injected_clock_plus_margin(client, clock) -> None:
    make_store(client, clock, retention_margin=timedelta(seconds=5)).record_once(KEY, NOW + 30.25)
    assert client.calls[0][3] == 35_250


def test_record_outlives_exp_by_the_retention_margin(client, clock) -> None:
    store = make_store(client, clock, retention_margin=timedelta(seconds=60))
    store.record_once(KEY, NOW + 10)
    clock.advance(10 + 59)
    with pytest.raises(AuthorizationError) as caught:
        store.record_once(KEY, NOW + 10)
    assert caught.value.reason is ReasonCode.REPLAY_DETECTED


def test_record_is_released_after_expiry(client, clock) -> None:
    store = make_store(client, clock, retention_margin=timedelta(0))
    store.record_once(KEY, NOW + 10)
    clock.advance(10)
    store.record_once(KEY, NOW + 20)


def test_expiry_inside_margin_is_still_recorded(client, clock) -> None:
    """A token accepted under verifier leeway after ``exp`` is still made single-use."""
    store = make_store(client, clock, retention_margin=timedelta(seconds=5))
    store.record_once(KEY, NOW - 2)
    assert client.calls[0][3] == 3_000
    with pytest.raises(AuthorizationError) as caught:
        store.record_once(KEY, NOW - 2)
    assert caught.value.reason is ReasonCode.REPLAY_DETECTED


@pytest.mark.parametrize("expires_at", [NOW, NOW - 1, NOW - 3600])
def test_expiry_already_past_is_denied_without_touching_redis(client, clock, expires_at) -> None:
    store = make_store(client, clock, retention_margin=timedelta(0))
    with pytest.raises(DependencyError) as caught:
        store.record_once(KEY, expires_at)
    assert caught.value.reason is ReasonCode.DEPENDENCY_UNAVAILABLE
    assert "past" in caught.value.detail
    assert client.calls == []


@pytest.mark.parametrize("expires_at", [math.nan, math.inf, -math.inf])
def test_non_finite_expiry_is_denied(client, clock, expires_at) -> None:
    with pytest.raises(DependencyError) as caught:
        make_store(client, clock).record_once(KEY, expires_at)
    assert caught.value.reason is ReasonCode.DEPENDENCY_UNAVAILABLE
    assert client.calls == []


def test_expiry_beyond_max_ttl_is_denied_not_truncated(client, clock) -> None:
    store = make_store(client, clock, max_ttl=timedelta(minutes=10))
    store.record_once(replay_key("ok", "op"), NOW + 600)
    with pytest.raises(DependencyError) as caught:
        store.record_once(KEY, NOW + 601)
    assert caught.value.reason is ReasonCode.DEPENDENCY_UNAVAILABLE
    assert "maximum" in caught.value.detail
    assert len(client.calls) == 1


# ------------------------------------------------------------------ fail closed


@pytest.mark.parametrize(
    "error",
    [
        RedisConnectionError("Error 61 connecting to replay.internal:6379"),
        RedisTimeoutError("Timeout reading from replay.internal:6379"),
        ResponseError("OOM command not allowed"),
        OSError("network unreachable"),
        TimeoutError("timed out"),
    ],
    ids=["connection", "timeout", "response", "os", "builtin-timeout"],
)
def test_redis_failure_denies_with_dependency_error(
    client, clock, error, caplog: pytest.LogCaptureFixture
) -> None:
    client.error = error
    with pytest.raises(DependencyError) as caught:
        make_store(client, clock).record_once(KEY, NOW + 60)
    assert caught.value.reason is ReasonCode.DEPENDENCY_UNAVAILABLE
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__ is True
    assert "replay.internal" not in str(caught.value)
    logged = " ".join(record.getMessage() for record in caplog.records)
    assert "replay.internal" not in logged
    assert "txn-9274" not in logged
    assert type(error).__name__ in logged


@pytest.mark.parametrize("reply", [False, "OK", b"OK", 1, 0, object()])
def test_unexpected_reply_denies(client, clock, reply) -> None:
    client.reply = reply
    with pytest.raises(DependencyError) as caught:
        make_store(client, clock).record_once(KEY, NOW + 60)
    assert caught.value.reason is ReasonCode.DEPENDENCY_UNAVAILABLE
    assert "unexpected" in caught.value.detail


async def test_async_client_is_denied_not_treated_as_success(client, clock) -> None:
    async def pending() -> bool:
        return True

    awaitable = pending()
    client.reply = awaitable
    try:
        with pytest.raises(DependencyError):
            make_store(client, clock).record_once(KEY, NOW + 60)
    finally:
        awaitable.close()


def test_unrelated_exception_propagates_instead_of_allowing(client, clock) -> None:
    client.error = RuntimeError("bug")
    with pytest.raises(RuntimeError):
        make_store(client, clock).record_once(KEY, NOW + 60)


def test_store_logs_nothing_about_keys_on_success(client, clock, caplog) -> None:
    caplog.set_level(logging.DEBUG, logger="pytrat.redis")
    store = make_store(client, clock)
    store.record_once(KEY, NOW + 60)
    with pytest.raises(AuthorizationError):
        store.record_once(KEY, NOW + 60)
    assert not [r for r in caplog.records if r.name.startswith("pytrat.redis")]


# ------------------------------------------------------------------ configuration


@pytest.mark.parametrize("prefix", ["", "has space:", "tab\t:", "nl\n:"])
def test_invalid_prefix_is_rejected(client, clock, prefix) -> None:
    with pytest.raises(ConfigurationError):
        make_store(client, clock, prefix=prefix)


@pytest.mark.parametrize("margin", [timedelta(seconds=-1), timedelta(hours=1, seconds=1)])
def test_invalid_retention_margin_is_rejected(client, clock, margin) -> None:
    with pytest.raises(ConfigurationError):
        make_store(client, clock, retention_margin=margin)


@pytest.mark.parametrize("max_ttl", [timedelta(0), timedelta(seconds=-5)])
def test_non_positive_max_ttl_is_rejected(client, clock, max_ttl) -> None:
    with pytest.raises(ConfigurationError):
        make_store(client, clock, max_ttl=max_ttl)


def test_default_clock_is_the_system_clock(client) -> None:
    import time

    RedisReplayStore(client).record_once(KEY, time.time() + 60)  # type: ignore[arg-type]
    assert 60_000 <= client.calls[0][3] <= 121_000


def test_from_url_configures_short_timeouts_and_no_retries() -> None:
    store = RedisReplayStore.from_url("redis://:hunter2@replay.internal:6379/0", socket_timeout=0.2)
    pool = store._client.connection_pool  # type: ignore[attr-defined]
    assert pool.connection_kwargs["socket_timeout"] == 0.2
    assert pool.connection_kwargs["socket_connect_timeout"] == 0.2
    assert pool.connection_kwargs["retry"].get_retries() == 0
    assert "hunter2" not in repr(store)


@pytest.mark.parametrize(
    "url", ["http://:hunter2@replay.internal:6379", "replay.internal:6379", "redis://:hunter2@h:x"]
)
def test_from_url_rejects_bad_urls_without_echoing_them(url) -> None:
    with pytest.raises(ConfigurationError) as caught:
        RedisReplayStore.from_url(url)
    assert "hunter2" not in str(caught.value)
    assert caught.value.__cause__ is None


@pytest.mark.parametrize("timeout", [0, -1, math.nan, math.inf])
def test_from_url_rejects_unbounded_timeouts(timeout) -> None:
    with pytest.raises(ConfigurationError):
        RedisReplayStore.from_url("redis://127.0.0.1:6379/0", socket_timeout=timeout)
