# pytrat-redis

<!-- --8<-- [start:usage] -->
Redis-backed `ReplayStore` for PyTraT deployments that run more than one process or instance.

```python
from pytrat.redis import RedisReplayStore

replay_store = RedisReplayStore.from_url(
    "rediss://replay.internal:6380/0",
    namespace="ledger-service",
)
replay_store.verify_configuration()  # at startup; see "Required Redis configuration"
pytrat = PyTraT(service="ledger", verifier=verifier, replay_store=replay_store)
```

Each first use is recorded with a single atomic `SET key 1 NX PX <ttl>`, so two instances racing
on the same transaction can never both succeed. Any Redis error or timeout raises
`DependencyError` and the request is denied.

## Required Redis configuration

> **`maxmemory-policy` MUST be `noeviction`.** Replay records carry a TTL, so under any
> `volatile-*` or `allkeys-*` policy Redis silently evicts them when it hits `maxmemory`, and a
> replayed token is then **accepted**. With `noeviction`, a full Redis refuses the `SET`, the store
> raises `DependencyError`, and the request is denied (503) instead.

Call `verify_configuration()` once at startup. It reads `CONFIG GET maxmemory-policy` and raises
`ConfigurationError` unless the policy is `noeviction`. Many managed Redis services disable
`CONFIG`; then it also raises `ConfigurationError`, telling you to verify `noeviction` through the
provider's console or API instead. Once you have, do not call the method. It checks the setting
only when called; a policy changed later at runtime is not detected.

Single use is only as durable as the records:

* **Persistence.** A Redis restart without persistence forgets every record, and every token
  still within its `exp` can be used once more. Enable AOF with `appendfsync everysec` (up to about
  one second of records can be lost on a crash) or `appendfsync always` (none, at a throughput
  cost). RDB snapshots alone lose everything since the last snapshot.
* **Failover.** Redis replication is asynchronous. If a primary fails over to a replica, records
  written in the last moments before the failure may be missing, and the matching tokens can be
  replayed once. Keep this window in your threat model; `WAIT`-based synchronous replication is not
  used by this store.

These windows are bounded by the token lifetime (plus the retention margin), because a record is
never needed after the token has expired.

## TLS

Use `rediss://` across any network you do not fully control. For `rediss://` URLs, `from_url`
explicitly sets `ssl_cert_reqs="required"` and `ssl_check_hostname=True`, so the server must present
a certificate that chains to a trusted root *and* names the host in the URL. Without the hostname
check, anyone holding any publicly trusted certificate could intercept the connection and answer
`OK` to every `SET NX`, defeating single use. A URL whose querystring disables either check (for
example `?ssl_check_hostname=false`) is refused with `ConfigurationError`. `redis>=6` is required.

When you pass your own `redis.Redis` client instead, configure the same verification yourself.

## Keys and namespaces

Keys are `prefix + namespace + ":" + SHA-256(replay key)`; raw `txn` values are never stored.

* `namespace` (required) is the name of the service using the store, for example
  `"ledger-service"`. Every instance of one service uses the same value; different services
  **must** use different values. Otherwise two services on one Redis that both mark, say,
  `POST /transfers` single-use would share records: the legitimate next hop would be denied, and
  any workload holding the token could burn it at one service to deny it at another.
  It must be printable, without spaces or `:`.
* `prefix` (default `pytrat:replay:`) separates environments or applications sharing one Redis.

## Timeouts

The store is synchronous and the FastAPI integration calls it on the event loop, so `from_url`
sets short socket timeouts (0.5 s by default) and disables client retries. When you pass your own
`redis.Redis` client, configure equivalent timeouts.

See the repository README for documentation.
<!-- --8<-- [end:usage] -->
