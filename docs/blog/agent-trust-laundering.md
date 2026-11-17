# Can an AI agent launder its trust?

*When agents delegate to other agents, the chain must never become more trusted than its least
trusted member. How Transaction Tokens for agents enforce that, and what they cannot do.*

---

Agent systems are starting to look like microservice call chains. A user asks an assistant to do
something. The assistant hands part of the work to a specialised agent, which calls a tool, which
calls an internal API. Each hop may run different code, from a different vendor, with a different
level of review.

Now the classic microservice question comes back with a twist. When the internal API receives a
request, it needs to know more than *which user* this is for. It needs to know *which agents*
handled the request on the way, and how far each one can be trusted.

## The laundering problem

Here is the scenario that worried me:

1. A user asks a **partner-supplied research agent** to produce a report. The organisation trusts
   it only a little: assurance `low`.
2. That agent delegates to the company's own **internal report agent**, built and reviewed
   in-house: assurance `high`.
3. The internal agent calls the reports service, which requires at least `medium`.

If the reports service only looks at the agent that called it (the internal, high-assurance one),
the request goes through. The low-assurance agent has used the trusted agent to get access it was
never supposed to have. Its trust has been *laundered* through the chain.

The fix is easy to state: **a chain's assurance is the minimum across every agent in it.** For
that, the minimum has to travel with the request, and nothing on the way should be able to raise
it.

## Transaction Tokens for agents

[Transaction Tokens](transaction-tokens-100-to-9000.md) already give us the right channel: a
short-lived token, signed by a trusted Transaction Token Service (TTS), that follows a request
through every hop. The individual draft
[`draft-araut-oauth-transaction-tokens-for-agents`](https://datatracker.ietf.org/doc/draft-araut-oauth-transaction-tokens-for-agents/)
adds an `agentic_ctx` claim with:

* the **originator**: the agent that started the chain,
* the **proximate agent**: the one acting right now,
* chain metadata: **hop count** and the chain's **minimum assurance level**.

When one agent delegates to another, the second agent's runtime asks the TTS to *replace* the
token. The TTS looks the new agent up in an **Agent Attribute Store** (managed by infrastructure,
never by an agent), then issues a new token. In the new token the proximate agent is updated, the
hop count goes up by one, and the minimum assurance is recomputed. It can only stay the same or
fall. The originator, the user and the transaction id never change.

[PyTraT](https://github.com/roshanlam/pytrat) implements this as the experimental `pytrat-agents`
package. Running the scenario above (`examples/agent-delegation`):

```text
1. User → external research agent (assurance: low)
   token:   originator=external-research-agent proximate=external-research-agent hops=1 min_assurance=low
2. External agent delegates to the internal report agent (assurance: high)
   token:   originator=external-research-agent proximate=internal-report-agent hops=2 min_assurance=low
3. Reports service (requires medium): DENIED (AGENT_ASSURANCE_INSUFFICIENT)
4. User → internal report agent directly
   token:   originator=internal-report-agent proximate=internal-report-agent hops=1 min_assurance=high
   Reports service: ALLOWED
5. One more agent hop beyond max_hops=2
   TTS: REFUSED (invalid_grant)
```

The trusted agent acting directly for the user is allowed. The same trusted agent, acting on
behalf of an untrusted one, is not. The resource never has to reconstruct the chain; the signed
minimum tells it.

## Monotonic, or it doesn't count

The whole guarantee rests on replacement *only attenuating*. So that is what PyTraT tests hardest.
Property-based tests generate arbitrary sequences of replacements and agents and check that:

* scope never grows,
* minimum assurance never rises,
* hop count rises by exactly one per agent hop,
* the originator, subject, audience and transaction id never change.

Two bugs in this area taught me where the edges are. Both were found by an adversarial review of
my own code:

**Absence is not a pass.** A route that required `minimum_assurance: medium` accepted a token with
*no* agent context at all. The reasoning in the code was "no agents, so nothing to check." But no
`agentic_ctx` doesn't prove that no agents were involved; it only proves the token doesn't say.
Now any agent requirement denies a token without agent context (`AGENT_CONTEXT_MISSING`). A pure
hop limit is the one exception, because zero hops always satisfies it.

**The requester must not name the agent.** The TTS accepts a few kinds of subject token. Some of
them are written by the requesting workload itself. Those could include an `act` claim naming an
agent, which would let a workload claim to be acting for the high-assurance agent and inherit its
assurance. Delegation must now come from an independent issuer's token. Requester-written subjects
with `act` are refused.

## Keep tokens away from the model

The other half of agent security is what the model can touch. If a model can see a token, a
prompt injection can try to exfiltrate it. If a model can call a token exchange, it can try to mint
broader ones.

PyTraT's `ToolRuntime` keeps both out of reach:

```python
runtime = ToolRuntime(agent=record, token_provider=provider, store=store, audit=sink)

@runtime.protected_tool(scope="billing.read", resource="billing-api")
def get_invoice(invoice_id: str) -> dict[str, str]:
    """Fetch one invoice."""
    ...

specs = runtime.tool_specs()                         # what the model is shown
result = runtime.call("get_invoice", {"invoice_id": "inv-42"})
```

* The model sees tool names, descriptions and argument schemas, never a token. The runtime offers
  no exchange, replacement or credential tool at all.
* Before each call the runtime obtains the token and checks the tool's scope and agent
  requirements. Arguments from the model are validated against the function's signature.
* Tool results pass through a guard that refuses to return anything shaped like a JWT, so a tool
  that accidentally echoes a credential cannot hand it to the model.

One honest caveat, which the documentation states plainly: **a Python decorator in the same process
as the model is not an isolation boundary.** If the model can execute code, it can reach anything
in that process. Run the tool runtime in a separate process, or behind a network boundary.

## What this does not solve

* The agent draft is an individual Internet-Draft, not a working-group document. PyTraT ships it as
  an experimental, separate package, and the reference TTS has it off by default. I reconciled
  every ambiguity I found in the draft and wrote the reconciliation up in the repository.
* Assurance levels are only as good as whoever assigns them. Transaction Tokens carry and enforce
  them; deciding that a partner agent is `low` is an organisational process.
* `session_id` and similar correlation hints are never used for authorization. They are easy to
  forge and were never meant to be trusted.

## Try it

```bash
pip install "pytrat[agents]"
git clone https://github.com/roshanlam/pytrat && cd pytrat && uv sync --all-packages
uv run python examples/agent-delegation/agent_delegation.py
```

If you are building multi-agent systems that call internal APIs, I'd like to know how you handle
trust across delegation today, and whether "minimum across the chain" matches what your security
team expects.
