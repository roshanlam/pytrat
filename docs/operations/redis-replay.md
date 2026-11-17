# Replay protection across instances (Redis)

!!! info "Coming with M9"
    A shared, Redis-backed replay store (`pytrat-redis`) is part of milestone M9 and is documented
    here when it lands.

Until then, `InMemoryReplayStore` is per process: with several replicas, a `single_use` resource
accepts a token once *per replica* (PyTraT profile P8). The `pytrat.core.ReplayStore` protocol is
the extension point; see [Policies](../guides/policies.md#replay-stores).
