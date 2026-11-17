# pytrat

OAuth **Transaction Tokens** for Python services and AI agents, implementing
[`draft-ietf-oauth-transaction-tokens-11`](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/11/)
with an experimental agent profile. A trusted Transaction Token Service signs what a request
authorized (who, which scope, which amount and accounts), and every downstream service verifies it
and checks that the operation it is about to perform is exactly that.

This package installs `pytrat-core`. Pick integrations with extras:

```bash
pip install "pytrat[fastapi]"     # resource services on FastAPI
pip install "pytrat[django]"      # resource services on Django
pip install "pytrat[client]"      # token exchange and propagation
pip install "pytrat[server]"      # the reference Transaction Token Service
pip install "pytrat[all]"         # everything, including agents, redis, otel and the CLI
```

| Extra | Package | Purpose |
|---|---|---|
| — | `pytrat-core` | Claims, strict verifier, `tctx` binding, workload authentication, audit, errors |
| `policy` | `pytrat-policy` | YAML policies and the shared enforcement pipeline |
| `client` | `pytrat-client` | RFC 8693 exchange, workload credentials, propagating HTTP client |
| `fastapi` / `django` | `pytrat-fastapi` / `pytrat-django` | Framework integrations that fail closed |
| `server` | `pytrat-server` | Reference Transaction Token Service |
| `agents` | `pytrat-agents` | Experimental AI-agent profile |
| `redis` | `pytrat-redis` | Replay protection shared across instances |
| `otel` | `pytrat-otel` | OpenTelemetry audit sink |
| `cli` | `pytrat-cli` | `pytrat keys / policy / token / tts` |

Status: pre-1.0 and not yet externally audited. Documentation, examples and the threat model:
<https://github.com/roshanlam/pytrat>.
