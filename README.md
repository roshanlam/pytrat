# PyTraT

**Transaction-bound, verifiable authorization context for Python services and AI agents.**

PyTraT implements OAuth **Transaction Tokens**
([`draft-ietf-oauth-transaction-tokens-11`](docs/spec/draft-ietf-oauth-transaction-tokens-11.txt))
with an experimental **agent profile**
([`draft-araut-oauth-transaction-tokens-for-agents-03`](docs/spec/draft-araut-oauth-transaction-tokens-for-agents-03.txt)).
A trusted Transaction Token Service signs a short-lived token recording *who* the transaction is
for and *what* was authorized: "transfer 10000 USD minor units from account-A to account-B". Every
downstream service verifies the token and checks that the operation it is about to perform is
exactly the one authorized.

It does not replace OAuth, authentication or your authorization logic. It gives them trusted
transaction context that survives every hop.

> **Status:** pre-1.0. Both specifications are Internet-Drafts; PyTraT targets exactly the
> revisions above. See [docs/compatibility.md](docs/compatibility.md).

## The 30-second demo

```bash
uv sync --all-packages
uv run python examples/payment-transfer/demo.py
```

```text
── Transfer $100.00 from account-A to account-B (honest services)
✔ 201 recorded: 100.00 USD (txn 01a1e862-…)

── Transfer $100.00 from account-A to account-B (compromised payment service)
✘ 403 TRANSACTION_CONTEXT_MISMATCH: Transaction not authorized
ledger entries recorded: 0
{ "event_type": "authorization.denied", "reason_code": "TRANSACTION_CONTEXT_MISMATCH",
  "detail": {"check": "'amount_minor': request value differs from the authorized value"}, … }
```

A compromised intermediary can change the request it forwards, but it holds no signing key, so it
cannot change what the token authorized. No Kubernetes, no containers; see
[examples/payment-transfer](examples/payment-transfer).

## Protecting a FastAPI route

```python
from typing import Annotated
from fastapi import Depends, FastAPI
from pydantic import BaseModel, ConfigDict

from pytrat.core import (
    StaticKeySet, TokenVerifier, VerifierSettings, WorkloadJwtAuthenticator, WorkloadKeys,
)
from pytrat.fastapi import PyTraT, Transaction

class Transfer(BaseModel):
    model_config = ConfigDict(strict=True)
    source_account: str
    destination_account: str
    amount_minor: int          # integer minor units: floats are never bindable
    currency: str

verifier = TokenVerifier(
    VerifierSettings(trust_domain="payments.internal"),
    StaticKeySet.from_jwks_file("tts.jwks.json"),          # trusted keys from configuration
)
pytrat = PyTraT(
    service="ledger-service",
    verifier=verifier,
    authenticator=WorkloadJwtAuthenticator(               # who is calling (independent of the token)
        WorkloadKeys({"payment-service": StaticKeySet.from_jwks_file("payment-service.jwks.json")}),
        audience="ledger-service",                         # identity = owner of the verifying key
    ),
    protected_prefixes=("/internal",),                    # forgotten routes fail closed
)
app = FastAPI(lifespan=pytrat.lifespan)
pytrat.install(app)

@app.post("/internal/ledger/entries")
async def record(
    transfer: Transfer,
    txn: Annotated[Transaction, Depends(pytrat.require_transaction(
        scope="payments.transfer",
        bind_fields=["source_account", "destination_account", "amount_minor", "currency"],
        allowed_callers=["payment-service"],
    ))],
):
    ...  # only reached if the body matches the token's tctx exactly
```

Per request, PyTraT:

1. reads exactly one `Txn-Token` header;
2. verifies the signature with a trusted key and an allowlisted algorithm, plus the Trust Domain
   (`aud`) and the token's lifetime;
3. authenticates the calling workload separately;
4. checks scope, the allowed callers, strict typed binding of the body to `tctx`, and any agent
   constraints;
5. emits one structured audit event;
6. binds the token so outbound `AsyncTransactionClient` calls forward it unchanged, and only to
   allowlisted hosts.

Django has the equivalent `@require_transaction` decorator and middleware
([pytrat-django](packages/pytrat-django)). Policies can also live in YAML; validate them with
`pytrat policy check policy.yaml`.

## Packages

| Package | Purpose | Depends on |
|---|---|---|
| [`pytrat-core`](packages/pytrat-core) | Claims, strict verifier, scopes, `tctx` binding, workload authenticators, audit, errors. No framework or HTTP dependencies. | PyJWT, Pydantic |
| [`pytrat-policy`](packages/pytrat-policy) | YAML policy model and compiler, plus `TransactionEnforcer`, the per-request pipeline shared by every integration. | core |
| [`pytrat-client`](packages/pytrat-client) | RFC 8693 exchange (sync and async), workload credentials, propagating HTTP client, JWKS refresh. | core, httpx |
| [`pytrat-fastapi`](packages/pytrat-fastapi) | Dependencies, fail-closed middleware, RFC 9457 errors, edge initiation. | core, policy, client |
| [`pytrat-django`](packages/pytrat-django) | Decorator, middleware, system checks. | core, policy, client |
| [`pytrat-server`](packages/pytrat-server) | Reference Transaction Token Service: RFC 7523 workload auth, issuance policy, replacement, key rotation, hash-chained audit log. | core, policy, agents |
| [`pytrat-agents`](packages/pytrat-agents) | *Experimental* agent profile: Agent Attribute Store, monotonic chain attenuation, trusted tool runtime. | core |
| [`pytrat-cli`](packages/pytrat-cli) | `pytrat keys`, `pytrat policy check`, `pytrat token inspect`, `pytrat tts serve`. | all |

Dependencies point one way only, and `import-linter` enforces it in CI (`.importlinter`).

## Security model in one paragraph

Verification fails closed. Keys come only from configuration, selected by `kid`; tokens can never
supply or point at their own key. `none` and `HS*` cannot be enabled. Tokens are wrapped in
`SecretToken`, so they never appear in logs, exceptions or audit events, and a repo-wide test
fixture fails any test that logs one. Context binding compares canonical values with exact types
(`True != 1`, `"10000" != 10000`, floats refused). Replacement only attenuates: `txn`, `sub`, `aud`,
`act` and the agent originator never change, scope only shrinks, assurance only falls. See
[docs/threat-model.md](docs/threat-model.md).

## Agents

```bash
uv run python examples/agent-delegation/agent_delegation.py
```

A low-assurance external agent delegating to a high-assurance internal agent still yields a `low`
chain, which a resource requiring `medium` denies. Hop limits are enforced by the TTS. The trusted
tool runtime (`pytrat.agents.ToolRuntime`) keeps tokens and exchange capabilities away from the
model. An in-process decorator is not an isolation boundary, so run the runtime outside the model's
process when the model can execute code.

## Development

```bash
uv sync --all-packages
uv run ruff format . && uv run ruff check .
uv run mypy                      # strict, whole workspace
uv run lint-imports              # dependency contracts
uv run pytest                    # 1400+ tests: unit, conformance, security, integration
uv run pytest benchmarks --benchmark-only
```

Contributor rules and security invariants: [CLAUDE.md](CLAUDE.md). Design and milestones:
[plan.md](plan.md). Vulnerability reports: [SECURITY.md](SECURITY.md).

### Measured performance

Local verification on an Apple-silicon laptop, single core, median: ES256 ≈ 64 µs, PS256 ≈ 46 µs,
cached repeat ≈ 1.2 µs, four-field `tctx` binding ≈ 2.7 µs. Reproduce with the benchmark command
above. These numbers are local CPU only; token exchange adds a network round trip to the TTS.

## License

Apache-2.0.
