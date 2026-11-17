# Replay protection across instances (Redis)

Txn-Tokens are not replay-resistant by design (txn-tokens-11 §13.1). PyTraT makes single use opt-in
per operation (`single_use=True`, profile decision P8). `InMemoryReplayStore` enforces it within one
process only. Once a service runs more than one process or instance, every instance must share one
store, or a token used on instance A can be replayed on instance B. `pytrat-redis` provides that
shared store.

!!! danger "Redis must run with `maxmemory-policy noeviction`"
    Replay records carry a TTL. Under any `volatile-*` or `allkeys-*` eviction policy, memory
    pressure silently evicts them and a replay is **accepted**. With `noeviction`, a full Redis
    rejects writes instead, and PyTraT denies the request with 503. Call
    `store.verify_configuration()` at startup.

--8<-- "packages/pytrat-redis/README.md:usage"
