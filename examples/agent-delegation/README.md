# Agent-delegation example (experimental agent profile)

Shows monotonic attenuation from `draft-araut-oauth-transaction-tokens-for-agents-03`: an external,
low-assurance agent cannot gain authority by delegating to a high-assurance internal agent.

```bash
uv run python examples/agent-delegation/agent_delegation.py
```

1. User → external research agent (`low`): Txn-Token with `agentic_ctx`, hop 1.
2. Delegation to the internal report agent (`high`): the TTS replaces the token; hop 2, proximate
   agent updated, chain minimum assurance stays `low`, `req_wl` becomes `edge,report-agent`.
3. The reports service requires `medium` → **denied** (`AGENT_ASSURANCE_INSUFFICIENT`).
4. The internal agent acting directly for the user (a `high` chain) → **allowed**.
5. A hop beyond `max_hops: 2` → **refused** by the TTS.

Runs in CI as `tests/integration/test_agent_delegation_example.py`.
