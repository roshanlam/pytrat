"""``verify_configuration`` and memory pressure against a real Redis.

These tests change server settings with ``CONFIG SET`` and restore them afterwards, so point
``PYTRAT_TEST_REDIS_URL`` only at a throwaway Redis. Skipped unless it is set.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Iterator

import pytest
import redis

from _redis_testkit import real_redis_url
from pytrat.core import ConfigurationError, DependencyError, ReasonCode, replay_key
from pytrat.redis import RedisReplayStore

pytestmark = pytest.mark.integration


@pytest.fixture
def admin() -> Iterator[redis.Redis]:
    """An admin connection; ``maxmemory`` and ``maxmemory-policy`` are restored afterwards."""
    client = redis.Redis.from_url(real_redis_url(), decode_responses=True)
    saved = {name: str(client.config_get(name)[name]) for name in ("maxmemory", "maxmemory-policy")}
    try:
        yield client
    finally:
        for name, value in saved.items():
            client.config_set(name, value)
        client.close()


def store() -> RedisReplayStore:
    return RedisReplayStore.from_url(
        real_redis_url(),
        prefix=f"pytrat-test:{secrets.token_hex(8)}:",
        namespace="ledger-service",
    )


def test_verify_configuration_passes_with_noeviction(admin: redis.Redis) -> None:
    admin.config_set("maxmemory-policy", "noeviction")
    store().verify_configuration()


@pytest.mark.parametrize("policy", ["volatile-lru", "allkeys-lru", "volatile-ttl"])
def test_verify_configuration_rejects_an_evicting_redis(admin: redis.Redis, policy: str) -> None:
    admin.config_set("maxmemory-policy", policy)
    with pytest.raises(ConfigurationError) as caught:
        store().verify_configuration()
    assert caught.value.reason is ReasonCode.POLICY_INVALID
    assert policy in caught.value.detail


def test_full_redis_with_noeviction_denies_instead_of_dropping_records(
    admin: redis.Redis,
) -> None:
    """With ``noeviction`` a full Redis refuses the write, so the request is denied (503)."""
    admin.config_set("maxmemory-policy", "noeviction")
    replay_store = store()
    replay_store.verify_configuration()
    admin.config_set("maxmemory", "1")
    with pytest.raises(DependencyError) as caught:
        replay_store.record_once(replay_key("txn-full", "op"), time.time() + 60)
    assert caught.value.reason is ReasonCode.DEPENDENCY_UNAVAILABLE
