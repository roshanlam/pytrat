# pytrat-agents

**Experimental.** The AI-agent profile of Transaction Tokens for PyTraT,
implementing `draft-araut-oauth-transaction-tokens-for-agents-03`, an individual Internet-Draft not
adopted by the OAuth working group. The API may change with every draft revision.

* `agentic_ctx` computation with **monotonic attenuation**: the originator never changes,
  `hop_count` only rises, the chain's minimum assurance only falls.
* The trusted **Agent Attribute Store** (`YamlAgentStore`, `SqliteAgentStore`, `InMemoryAgentStore`).
* Resource-side agent-chain requirements.
* `ToolRuntime`, a trusted tool runtime that keeps tokens and exchange capabilities away from the
  model, validates tool arguments strictly and blocks token-shaped tool results.

```bash
pip install pytrat-agents
```

```python
from pytrat.agents import AgentRecord, InMemoryAgentStore, ToolRuntime

agent = AgentRecord(id="report-agent", name="Report agent", owner="finance", assurance_level="high",
                    version="2.4.1", provenance="sha256:...")
runtime = ToolRuntime(agent=agent, token_provider=provider, store=InMemoryAgentStore([agent]),
                      audit=sink)


@runtime.protected_tool(scope="reports.read", resource="reports-api")
def get_report(report_id: str) -> dict[str, str]:
    """Fetch one report."""  # never receives the token
    ...
```

> **An in-process decorator is not an isolation boundary.** If the model can execute code in the
> same process, it can reach the token provider. Run the runtime in a separate process or sidecar.

## Documentation

PyTraT documentation: *Agents (experimental)* and the `pytrat.agents` API reference (sources in
`docs/` of the repository).

Apache-2.0.
