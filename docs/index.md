# PyTraT

**Transaction-bound, verifiable authorization context for Python services and AI agents.**

PyTraT implements OAuth **Transaction Tokens**
([`draft-ietf-oauth-transaction-tokens-11`](spec/draft-ietf-oauth-transaction-tokens-11.txt))
with an experimental **agent profile**
([`draft-araut-oauth-transaction-tokens-for-agents-03`](spec/draft-araut-oauth-transaction-tokens-for-agents-03.txt)).

A trusted Transaction Token Service (TTS) signs a short-lived token recording *who* the
transaction is for and *what* was authorized: "transfer 10000 USD minor units from account-A to
account-B". Every downstream service verifies the token and checks that the operation it is about
to perform is exactly the one authorized.

It does not replace OAuth, authentication or your authorization logic. It gives them trusted
transaction context that survives every hop.

!!! warning "Status: pre-1.0"
    Both specifications are Internet-Drafts. PyTraT targets exactly the revisions above and claims
    nothing about any other. See [Protocol compatibility](compatibility.md).

## The 30-second demo

```bash
pip install "pytrat[all]"
pytrat demo
```

```text
1. Every service is honest
   ledger: 201 recorded 100.00 USD

2. payment-service is compromised and rewrites $100.00 to $9,000.00
   ledger: 403 refused (TRANSACTION_CONTEXT_MISMATCH)
   ledger entries recorded: 0
   ledger audit event:
   { "event_type": "authorization.denied", "reason_code": "TRANSACTION_CONTEXT_MISMATCH",
     "detail": {"check": "'amount_minor': request value differs from the authorized value"}, … }
```

A compromised intermediary can change the request it forwards, but it holds no signing key, so it
cannot change what the token authorized. The demo runs four services in-process (gateway, payment,
ledger and the reference TTS); see [Concepts](concepts.md#the-payment-flow) for the full sequence.

## What PyTraT does on every protected request

1. Reads exactly one `Txn-Token` header (never `Authorization`).
2. Verifies the signature with a **trusted** key and an **allowlisted** algorithm, plus the Trust
   Domain (`aud`) and the token's lifetime.
3. Authenticates the calling workload **separately**: a Transaction Token is not authentication.
4. Checks scope, the allowed callers, strict typed binding of the request to `tctx`, and any agent
   constraints.
5. Emits one structured audit event.
6. Binds the token so outbound calls forward it unchanged, and only to allowlisted hosts.

Anything missing (key, policy, claim, registry entry, dependency) means **deny**.

## Where to go next

<div class="grid cards" markdown>

- **[Getting started](getting-started.md)**: install, generate keys, protect a FastAPI route and
  test it.
- **[Concepts](concepts.md)**: Trust Domains, the TTS, claims, `tctx` binding, replacement.
- **Guides**: [FastAPI](guides/fastapi.md), [Django](guides/django.md),
  [Client](guides/client.md), [Running the TTS](guides/tts.md), [Policies](guides/policies.md),
  [Agents](guides/agents.md), [CLI](guides/cli.md), [Errors](guides/errors.md).
- **[Security](threat-model.md)**: threat model, profile decisions, reporting vulnerabilities.

</div>

## Packages

| Package | Purpose | Depends on |
|---|---|---|
| `pytrat-core` | Claims, strict verifier, scopes, `tctx` binding, workload authenticators, audit, errors. No framework or HTTP dependencies. | PyJWT, Pydantic |
| `pytrat-policy` | YAML policy model and compiler, plus `TransactionEnforcer`, the per-request pipeline shared by every integration. | core, PyYAML |
| `pytrat-client` | RFC 8693 exchange (sync and async), workload credentials, propagating HTTP client, JWKS refresh. | core, httpx |
| `pytrat-fastapi` | Dependencies, fail-closed middleware, RFC 9457 errors, edge initiation. | core, policy, client, FastAPI |
| `pytrat-django` | Decorator, middleware, system checks. | core, policy, client, Django |
| `pytrat-server` | Reference TTS: RFC 7523 workload auth, issuance policy, replacement, key rotation, hash-chained audit log. | core, policy, agents, FastAPI, uvicorn |
| `pytrat-agents` | *Experimental* agent profile: Agent Attribute Store, monotonic chain attenuation, trusted tool runtime. | core, PyYAML |
| `pytrat-cli` | `pytrat keys`, `pytrat policy check`, `pytrat token inspect`, `pytrat tts serve`. | all of the above, Typer |

Every package ships a slice of the PEP 420 `pytrat` namespace (`pytrat.core`, `pytrat.fastapi`,
...). Dependencies point one way only, and `import-linter` enforces it in CI.

## Security model in one paragraph

Verification fails closed. Keys come only from configuration, selected by `kid`; tokens can never
supply or point at their own key. `none` and `HS*` cannot be enabled. Tokens are wrapped in
`SecretToken`, so they never appear in logs, exceptions or audit events, and a repository-wide test
fixture fails any test that logs one. Context binding compares canonical values with exact types
(`True != 1`, `"10000" != 10000`, floats refused). Replacement only attenuates: `txn`, `sub`, `aud`,
`act` and the agent originator never change, scope only shrinks, assurance only falls. See the
[threat model](threat-model.md).

## License

Apache-2.0.
