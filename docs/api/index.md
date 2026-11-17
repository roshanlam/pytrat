# API reference

One page per package, generated from the docstrings of each package's public API
(`__all__`). Every package ships a slice of the PEP 420 `pytrat` namespace, so there is no
top-level `pytrat` module.

| Package | Import | Page |
|---|---|---|
| `pytrat-core` | `pytrat.core` | [pytrat.core](core.md) |
| `pytrat-policy` | `pytrat.policy` | [pytrat.policy](policy.md) |
| `pytrat-client` | `pytrat.client` | [pytrat.client](client.md) |
| `pytrat-fastapi` | `pytrat.fastapi` | [pytrat.fastapi](fastapi.md) |
| `pytrat-django` | `pytrat.django` | [pytrat.django](django.md) |
| `pytrat-server` | `pytrat.server` | [pytrat.server](server.md) |
| `pytrat-agents` | `pytrat.agents` | [pytrat.agents](agents.md) (experimental) |
| `pytrat-cli` | `pytrat.cli` | [pytrat.cli](cli.md) |

Dependencies point one way only (`core ← policy ← fastapi/django`, `core ← client`,
`core ← agents ← server`, everything `← cli`); `import-linter` enforces this in CI.
