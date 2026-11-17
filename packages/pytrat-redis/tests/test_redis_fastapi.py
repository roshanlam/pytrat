"""Two FastAPI instances of one service share a RedisReplayStore (PyTraT profile P8).

A single-use operation performed through instance A must be rejected when the same token is
replayed against instance B. The Redis server is the in-process fake; the store, the policy
pipeline and the FastAPI integration are real.
"""

# No ``from __future__ import annotations``: FastAPI must resolve the route's local dependency.
from typing import Annotated

import httpx
import pytest
from fastapi import Depends, FastAPI

from _redis_testkit import FakeRedisClient, FakeRedisServer
from pytrat.core.testing import TokenFactory
from pytrat.fastapi import PyTraT, Transaction
from pytrat.redis import RedisReplayStore

pytestmark = pytest.mark.integration


def instance(factory: TokenFactory, server: FakeRedisServer) -> tuple[FastAPI, PyTraT]:
    store = RedisReplayStore(FakeRedisClient(server), clock=factory.clock)
    pytrat = PyTraT(service="ledger", verifier=factory.verifier(), replay_store=store)
    app = FastAPI(lifespan=pytrat.lifespan)
    pytrat.install(app)
    requirement = pytrat.require_transaction(
        scope="payments.transfer",
        single_use=True,
        require_workload_identity=False,
        policy_id="ledger.transfer",
    )

    @app.post("/transfer")
    async def transfer(txn: Annotated[Transaction, Depends(requirement)]) -> dict[str, str]:
        return {"txn": txn.id}

    return app, pytrat


async def post(app: FastAPI, pytrat: PyTraT, token: str) -> httpx.Response:
    async with (
        pytrat.lifespan(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://ledger.internal"
        ) as client,
    ):
        return await client.post("/transfer", headers={"Txn-Token": token})


async def test_single_use_replay_against_another_instance_is_rejected() -> None:
    factory = TokenFactory.create()
    shared_redis = FakeRedisServer(clock=factory.clock)
    app_a, pytrat_a = instance(factory, shared_redis)
    app_b, pytrat_b = instance(factory, shared_redis)
    token = factory.mint()

    first = await post(app_a, pytrat_a, token)
    replayed = await post(app_b, pytrat_b, token)
    other_txn = await post(app_b, pytrat_b, factory.mint(txn="txn-other"))

    assert first.status_code == 200
    assert replayed.status_code == 403
    assert replayed.json()["reason_code"] == "REPLAY_DETECTED"
    assert other_txn.status_code == 200


async def test_redis_outage_denies_with_503() -> None:
    factory = TokenFactory.create()
    shared_redis = FakeRedisServer(clock=factory.clock)
    app, pytrat = instance(factory, shared_redis)
    store = pytrat._replay_store
    assert isinstance(store, RedisReplayStore)
    from redis.exceptions import ConnectionError as RedisConnectionError

    store._client.error = RedisConnectionError("down")  # type: ignore[attr-defined]
    response = await post(app, pytrat, factory.mint())
    assert response.status_code == 503
    assert response.json()["reason_code"] == "DEPENDENCY_UNAVAILABLE"
