# pytrat-redis

Redis-backed `ReplayStore` for PyTraT deployments that run more than one process or instance.

```python
from pytrat.redis import RedisReplayStore

replay_store = RedisReplayStore.from_url("redis://replay.internal:6379/0")
pytrat = PyTraT(service="ledger", verifier=verifier, replay_store=replay_store)
```

Each first use is recorded with a single atomic `SET key 1 NX PX <ttl>`, so two instances racing
on the same transaction can never both succeed. Keys are a configurable prefix plus the SHA-256
of the replay key; raw `txn` values are never stored. Any Redis error or timeout raises
`DependencyError` and the request is denied.

The store is synchronous and the FastAPI integration calls it on the event loop, so `from_url`
sets short socket timeouts (0.5 s by default) and disables client retries. When you pass your own
`redis.Redis` client, configure equivalent timeouts.

See the repository README for documentation.
