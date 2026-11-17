# Agents (experimental)

!!! warning "Experimental"
    `pytrat-agents` implements `draft-araut-oauth-transaction-tokens-for-agents-03`, an individual
    Internet-Draft that has **not** been adopted by the OAuth working group. The package, its claims
    and its API may change with every draft revision. `pytrat.agents.PROFILE_VERSION` names the
    revision implemented. Where the draft is ambiguous PyTraT chose the more restrictive reading;
    every choice is listed in [the reconciliation notes](../spec/agent-profile-03-notes.md) and as
    P17–P22, P28 and P30 in [Protocol compatibility](../compatibility.md).

When an AI agent acts on a user's behalf, and especially when agents delegate to other agents, a
resource needs to know more than *who* the transaction is for: which agent started the chain,
which agent is calling now, how many agents were involved, and how trustworthy the weakest of them
is. The agent profile records this in a Txn-Token claim, `agentic_ctx`, maintained only by the TTS.

## The `agentic_ctx` claim

```json
{
  "agentic_ctx": {
    "originator":      {"id": "research-agent", "session_id": "…"},
    "proximate_agent": {"id": "report-agent",   "session_id": "…"},
    "chain_metadata":  {"hop_count": 2, "min_assurance_level": "low"},
    "attr_store_ref":  "https://aas.payments.internal"
  }
}
```

| Member | Meaning |
|---|---|
| `originator` | The agent that started the chain. Never changes. |
| `proximate_agent` | The agent that obtained the current token (the most recent hop). |
| `chain_metadata.hop_count` | 1 at issuance, +1 for every agent replacement. Only rises. |
| `chain_metadata.min_assurance_level` | The minimum assurance across every agent in the chain. Only falls. |
| `attr_store_ref` | Optional, informational, internal. |

!!! note "`session_id` is a correlation hint"
    `session_id` values are never an authorization input and are deliberately not recorded in
    audit events. Do not build decisions on them.

## Monotonic attenuation

A chain can never become more trusted than its least trusted agent. When a `low`-assurance external
agent delegates to a `high`-assurance internal agent, the internal agent's replacement token still
says `min_assurance_level: low`, so a resource that requires `medium` denies it: the external agent
cannot launder its assurance through a trusted one. The TTS enforces `max_hops` on every
replacement (P17), and `txn`, `sub`, `aud`, `act` and `originator` never change.

```bash
uv run python examples/agent-delegation/agent_delegation.py
```

The example walks through exactly this: a delegated `low` chain is denied
(`AGENT_ASSURANCE_INSUFFICIENT`), the internal agent acting directly (a `high` chain) is allowed,
and a hop beyond `max_hops: 2` is refused by the TTS.

## TTS configuration

Enable the profile and point the TTS at the trusted **Agent Attribute Store**. See the
[`agents` settings](tts.md#agents-experimental) for every key.

```yaml
agents:
  enabled: true
  max_hops: 5
  registry_path: agents.yaml
```

The store is managed by authenticated infrastructure, never by an agent or a model:

```yaml title="agents.yaml"
--8<-- "docs/snippets/agents.yaml"
```

At issuance the agent is identified from the subject token's `act.sub`, then the store, then
`client_id` (P18). Requester-asserted subjects (self-signed, unsigned) may not carry `act` (P28),
and a client-credentials token that carries `act` is rejected (P19). On replacement the requesting
agent is identified from the requester's authenticated identity, never from the token.
`YamlAgentStore`, `SqliteAgentStore` and `InMemoryAgentStore` implement the `AgentAttributeStore`
protocol.

## Resource constraints

Resources constrain agent-mediated requests with the `agents` block of a
[YAML policy](policies.md#agents-block), or inline with `pytrat.policy.AgentRequirements`
([FastAPI example](fastapi.md#agents)):

| Constraint | Denies with |
|---|---|
| `maximum_hops` | `AGENT_HOP_LIMIT_EXCEEDED` |
| `minimum_assurance` | `AGENT_ASSURANCE_INSUFFICIENT` (also when the level is absent or unknown) |
| `allowed_originators` | `AGENT_NOT_ALLOWED` |
| `require_verified_agent` | `AGENT_UNVERIFIED` (originator and proximate agent must be in the store) |
| `require_agent_context` | `AGENT_CONTEXT_MISSING` |

Every constraint except `maximum_hops` also denies a token without `agentic_ctx` (P30).

## The trusted tool runtime

agent-profile-03 §3.7 splits an agent into an *inference layer* (the model) and an
*infrastructure layer* that executes tool calls and talks to the TTS. Token exchange must not be
exposed as a tool, and credentials must not appear in the model's context. `ToolRuntime` is the
infrastructure-layer piece:

```python
--8<-- "docs/snippets/agent_runtime.py"
```

For every call the runtime:

1. asks your `token_provider` for the verified token (it may perform a replacement); the provider
   is told the tool name, resource and scope, never the model-supplied arguments;
2. checks that the token covers the tool's `scope` (`SCOPE_INSUFFICIENT`), that this agent is the
   `proximate_agent` (`require_replacement`), and the agent requirements;
3. validates the arguments strictly against the function's annotations (`TOOL_ARGUMENTS_INVALID`);
4. runs the tool, which never receives the token;
5. scans the result and refuses (or, with `result_mode=ResultMode.REDACT`, redacts) anything shaped
   like a compact JWS (`TOOL_RESULT_BLOCKED`);
6. emits one audit event.

`runtime.tool_specs()` describes only the registered tools (name, description, JSON Schema) for
the model; no exchange, replacement or credential capability is ever listed, and tools whose names
or parameter types look like credential operations are refused at registration. Dispatch
model-requested calls with `runtime.call(name, arguments)` (or `acall` for async tools).

!!! danger "An in-process decorator is not an isolation boundary"
    Code running in the same interpreter as the runtime, including any code the model can
    influence (a code-execution tool, a plugin, a deserialised object), can read the token
    provider's memory, monkey-patch `pytrat.agents`, or call the provider directly. The guarantees
    above hold only if the inference layer **cannot execute arbitrary code in this process**.

    Run the runtime as a separate process or sidecar from the model, with the token provider and
    TTS credentials only on the runtime's side, and use out-of-band attestation to show that you
    did (agent-profile-03 §3.7, §5.16).

## Egress

`attr_store_ref` is an internal reference. Before a token's agent context leaves the Trust Domain,
remove it with `pytrat.agents.strip_for_egress` (agent-profile-03 §5.13, P21).
