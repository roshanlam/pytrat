# PyTraT

[![PyPI](https://img.shields.io/pypi/v/pytrat)](https://pypi.org/project/pytrat/)
[![Python](https://img.shields.io/pypi/pyversions/pytrat-core)](https://pypi.org/project/pytrat-core/)
[![License](https://img.shields.io/pypi/l/pytrat)](LICENSE)

**Your API gateway checked that the user may send $100. Does your ledger know that, or does it
just trust whatever the payment service sent it?**

PyTraT makes every service in a call chain prove that the operation it is about to perform is the
one the user actually authorized. It implements OAuth **Transaction Tokens**
([`draft-ietf-oauth-transaction-tokens-11`](docs/spec/draft-ietf-oauth-transaction-tokens-11.txt),
IETF OAuth Working Group), with an experimental profile for **AI agents**.

```bash
pip install "pytrat[all]"
pytrat demo
```

## The problem

A user's request enters at the edge, where it is authenticated and authorized. Then it fans out
across internal services, and the authorization context is usually lost. Internal services fall
back on one of two habits:

* **Trust the network.** Anything inside the cluster, or anything with a valid mTLS certificate, is
  allowed to call the ledger. Once one service is compromised, it can ask the ledger for anything.
* **Forward the user's access token.** That token is broad ("may make payments") and long-lived,
  and every service that holds it can replay it. It says nothing about *this* payment.

Neither one stops a compromised or buggy service in the middle of the chain from turning "transfer
$100 to Bob" into "transfer $9,000 to Mallory".

## What PyTraT does

At the edge, a trusted **Transaction Token Service (TTS)** signs a short-lived token recording who
the transaction is for and exactly what was authorized:

```json
{ "txn": "01a1e862-…", "sub": "user:123", "scope": "payments.transfer",
  "tctx": { "source_account": "account-A", "destination_account": "account-B",
            "amount_minor": 10000, "currency": "USD" } }
```

Every downstream service forwards that token unchanged. Before acting, each service verifies it
and compares the request it received against what the token authorized, field by field and with
exact types. An intermediary can rewrite the request, but it holds no signing key, so it cannot
rewrite the authorization:

```text
$ pytrat demo
1. Every service is honest
   ledger: 201 recorded 100.00 USD

2. payment-service is compromised and rewrites $100.00 to $9,000.00
   ledger: 403 refused (TRANSACTION_CONTEXT_MISMATCH)
   ledger entries recorded: 0
   ledger audit event:
   { "event_type": "authorization.denied", "reason_code": "TRANSACTION_CONTEXT_MISMATCH",
     "detail": {"check": "'amount_minor': request value differs from the authorized value"}, … }
```

That runs a gateway, a payment service, a ledger and the reference TTS in-process, with fresh keys
and no containers. The same services also run as four containers with verified TLS on every hop
([examples/payment-transfer](examples/payment-transfer)).

## Why use it

* **A compromised service cannot escalate.** It can only perform the exact operation the user
  authorized, and only while its short-lived token is valid.
* **Least privilege per transaction, not per service.** Access is scoped to *this* transfer, not
  to "payments in general".
* **It fits your existing stack.** You keep your identity provider, OAuth tokens and service
  identity. PyTraT adds transaction context on top and replaces none of them.
* **One audit trail per transaction.** Every service emits a structured audit event keyed by the
  same transaction id, so "who authorized this, and which hop refused it?" has an answer.
* **Built on a standard.** It follows an IETF draft rather than a home-grown header format,
  including the RFC 8693 token exchange and RFC 9457 error responses.
* **Ready for AI agents.** An agent's tool calls carry the same transaction context, and delegation
  between agents can only narrow authority, never widen it.
* **Quick to adopt.** `pytrat init` gives you a working service, TTS and tests in one command,
  and the `pytrat_kit` pytest fixture means tests never need a running TTS.
* **Hard to misconfigure.** Verification fails closed, `none` and `HS*` algorithms cannot be
  enabled, and a protected route you forgot to annotate is denied, not left open.

| | Trust the network / mTLS | Forward the access token | **PyTraT** |
|---|---|---|---|
| Knows which *workload* is calling | ✔ (mTLS) | ✘ | ✔ (separate workload auth) |
| Knows which *user* the call is for | ✘ | ✔ | ✔ |
| Knows *what* the user authorized (amount, accounts) | ✘ | ✘ | ✔ |
| A compromised middle service can change the operation | ✔ | ✔ | **✘** |
| Lifetime | — | minutes to hours | seconds to minutes |
| Audit trail spans every hop | ✘ | ✘ | ✔ |

## Start a project

```bash
pip install "pytrat[fastapi,server,cli]" pytest
pytrat init my-service          # dev keys, a TTS config, a protected service, tests, a caller
cd my-service && pytest         # 5 passed, with no TTS running
```

The generated `README.md` runs the TTS, the service and a gateway as three real processes: the
honest order gets `201`, and the same token with a changed quantity gets `403`.

## Protect a FastAPI route

```bash
pip install "pytrat[fastapi,cli]"
pytrat keys generate --kid tts-2026-11 --out keys/       # the TTS signing key (dev only)
pytrat keys generate --kid payment-service --out keys/   # the calling workload's key
```

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
    StaticKeySet.from_jwks_file("keys/tts-2026-11.jwks.json"),  # trusted keys from configuration
)
pytrat = PyTraT(
    service="ledger-service",
    verifier=verifier,
    authenticator=WorkloadJwtAuthenticator(               # who is calling (independent of the token)
        WorkloadKeys({"payment-service": StaticKeySet.from_jwks_file("keys/payment-service.jwks.json")}),
        audience="ledger-service",
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
    ...  # only reached if the body matches what the token authorized, exactly
```

For each request, PyTraT:

1. reads exactly one `Txn-Token` header;
2. verifies the signature with a trusted key and an allowlisted algorithm, then checks the Trust
   Domain (`aud`) and the token's lifetime;
3. authenticates the calling workload separately (a Transaction Token is not authentication);
4. checks the scope, the allowed callers, strict typed binding of the body to `tctx`, and any agent
   constraints;
5. emits one structured audit event;
6. forwards the token unchanged on outbound `AsyncTransactionClient` calls, and only to
   allowlisted hosts.

Testing needs no TTS. Installing `pytrat` adds a pytest fixture, `pytrat_kit`, that stands in
for the TTS and for the calling workloads:

```python
def test_tampered_amount_is_refused(client, pytrat_kit):
    headers = pytrat_kit.headers(scope="payments.transfer", tctx=TRANSFER,
                                 caller="payment-service", audience="ledger-service")
    response = client.post("/internal/ledger/entries", json={**TRANSFER, "amount_minor": 900_000},
                           headers=headers)
    assert response.json()["reason_code"] == "TRANSACTION_CONTEXT_MISMATCH"
```

See [Testing](docs/guides/testing.md) for the whole fixture. Django has the equivalent `@require_transaction` decorator and middleware
([pytrat-django](packages/pytrat-django)), and route rules can live in a reviewed YAML policy
(`pytrat policy check policy.yaml`).

## AI agents

When an agent calls tools that call services, the same question applies: is this tool call what
the user asked for? The experimental agent profile
([`draft-araut-oauth-transaction-tokens-for-agents-03`](docs/spec/draft-araut-oauth-transaction-tokens-for-agents-03.txt))
records the agent chain in the token, and authority only ever narrows along it. A low-assurance
external agent that delegates to a high-assurance internal agent still yields a `low` chain, so a
resource requiring `medium` refuses it:

```bash
uv run python examples/agent-delegation/agent_delegation.py   # from a clone
```

The trusted tool runtime (`pytrat.agents.ToolRuntime`) keeps tokens and token-exchange capabilities
out of the model's reach. An in-process decorator is not an isolation boundary, so when the model
can execute code, run the runtime in a separate process.

## Security model

Verification fails closed. Keys come only from configuration, selected by `kid`, and a token can
never supply or point at its own key. `none` and `HS*` cannot be enabled. Tokens are wrapped in
`SecretToken`, so they never appear in logs, exceptions or audit events; a repo-wide test fixture
fails any test that logs one. Context binding compares canonical values with exact types
(`True != 1`, `"10000" != 10000`, floats refused). Replacement only attenuates: `txn`, `sub`, `aud`,
`act` and the agent originator never change, scope only shrinks, assurance only falls. See
[docs/threat-model.md](docs/threat-model.md).

The codebase has 1,900+ tests: unit, spec-conformance, written-as-attack security tests, and
integration. It also runs nightly Atheris fuzzing of every parser that sees untrusted input, and
has had two independent adversarial reviews, with each finding fixed under a regression test.

**Performance.** Local verification on an Apple-silicon laptop (single core, median): ES256 ≈ 64 µs,
PS256 ≈ 46 µs, cached repeat ≈ 1.2 µs, four-field `tctx` binding ≈ 2.7 µs. Token exchange adds one
network round trip to the TTS at the edge. Full report: [docs/benchmarks.md](docs/benchmarks.md).

## Is it ready?

PyTraT is **pre-1.0**. Be clear about these before deploying it:

* Both specifications are Internet-Drafts. PyTraT targets exactly the revisions above and records
  every choice the drafts leave open in [docs/compatibility.md](docs/compatibility.md).
* There has been **no external third-party security audit** yet; the brief is
  [docs/security/audit.md](docs/security/audit.md).
* You need a Transaction Token Service. `pytrat-server` is a complete reference implementation
  (issuance policy, key rotation, rate limiting, hash-chained audit log). Any TTS that implements
  the same draft also works.

## Packages

Install `pytrat` with the extras you need, for example `pip install "pytrat[fastapi]"`.

| Extra | Package | Purpose |
|---|---|---|
| — | [`pytrat-core`](packages/pytrat-core) | Claims, strict verifier, scopes, `tctx` binding, workload authenticators, audit, errors. No framework or HTTP dependencies. |
| `policy` | [`pytrat-policy`](packages/pytrat-policy) | YAML policy model and compiler, plus `TransactionEnforcer`, the per-request pipeline shared by every integration. |
| `client` | [`pytrat-client`](packages/pytrat-client) | RFC 8693 exchange (sync and async), workload credentials, propagating HTTP client, JWKS refresh. |
| `fastapi` | [`pytrat-fastapi`](packages/pytrat-fastapi) | Dependencies, fail-closed middleware, RFC 9457 errors, edge initiation. |
| `django` | [`pytrat-django`](packages/pytrat-django) | Decorator, middleware, system checks. |
| `server` | [`pytrat-server`](packages/pytrat-server) | Reference Transaction Token Service. |
| `agents` | [`pytrat-agents`](packages/pytrat-agents) | *Experimental* agent profile: Agent Attribute Store, monotonic chain attenuation, trusted tool runtime. |
| `redis` | [`pytrat-redis`](packages/pytrat-redis) | Shared replay store for single-use tokens across instances. |
| `otel` | [`pytrat-otel`](packages/pytrat-otel) | OpenTelemetry audit sink. |
| `cli` | [`pytrat-cli`](packages/pytrat-cli) | `pytrat demo`, `init`, `keys`, `policy check`, `token inspect`, `tts serve`. |

Dependencies point one way only, and `import-linter` enforces it in CI (`.importlinter`).

## Documentation

**<https://pytrat.readthedocs.io/>** has the guides, concepts, configuration reference and API
reference. Start with [Getting started](https://pytrat.readthedocs.io/en/latest/getting-started/)
and [Concepts](https://pytrat.readthedocs.io/en/latest/concepts/). The sources are in
[`docs/`](docs/index.md); `uv run --group docs mkdocs serve` previews them from a clone.

## Development

```bash
uv sync --all-packages
uv run ruff format . && uv run ruff check .
uv run mypy                      # strict, whole workspace
uv run lint-imports              # dependency contracts
uv run pytest                    # unit, conformance, security, integration
uv run pytest benchmarks --benchmark-only
```

Contributor rules and security invariants: [CLAUDE.md](CLAUDE.md). Design and milestones:
[plan.md](plan.md). Vulnerability reports: [SECURITY.md](SECURITY.md).

## License

Apache-2.0.
