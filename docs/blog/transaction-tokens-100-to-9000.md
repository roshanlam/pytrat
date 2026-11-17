# A $100 transfer, a compromised service, and $9,000

*How OAuth Transaction Tokens stop an intermediary from changing what a user authorized, and how
to use them in Python with PyTraT.*

---

Here is a call chain that every microservice team has some version of:

```text
user ──► api-gateway ──► payment-service ──► ledger-service
         (OAuth token)    (internal call)     (internal call)
```

The user asks to move **$100** from account A to account B. The gateway validates the user's
access token and calls the payment service. The payment service calls the ledger. The ledger
writes the entry.

Now suppose the payment service is compromised: a vulnerable dependency, a leaked deploy key,
anything. It forwards the request but changes one field:

```json
{"source_account": "account-A", "destination_account": "account-B",
 "amount_minor": 900000, "currency": "USD"}
```

That is $9,000. What stops the ledger from writing it?

In most systems, nothing in the request itself. The ledger authenticates the *caller* (mTLS,
a service mesh identity, an internal API key). It knows the request came from the payment service,
and the payment service is allowed to post transfers. The user's intent, *$100 from A to B*, was
checked at the edge and then evaporated. Every hop after the gateway is trusted to carry it
honestly.

## What a Transaction Token is

The IETF OAuth working group's
[Transaction Tokens draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/)
addresses exactly this. At the edge, a trusted **Transaction Token Service (TTS)** exchanges the
user's access token for a short-lived, signed JWT that records:

* **who** the transaction is for (`sub`),
* **what** was authorized (`scope`, plus a `tctx` object with the parameters: amount, accounts,
  currency),
* **where** it is valid (`aud`, the trust domain),
* a transaction id (`txn`) that follows the request through every hop,
* and which workload asked for it (`req_wl`).

That token travels with the request in a `Txn-Token` header. Every service verifies the signature
with the TTS's public keys and compares the operation it is about to perform with `tctx`.

The compromised payment service can still change the body. But it holds no signing key, so it
cannot change the token. The ledger sees `amount_minor: 900000` in the body and
`amount_minor: 10000` in the token, and refuses.

Two properties matter:

1. **Integrity of intent.** The parameters the user authorized are signed once, at the edge, by a
   service whose only job is issuing these tokens.
2. **It is not authentication.** A Transaction Token says *what* this request is allowed to do. It
   does not prove *who* is calling. Services still authenticate each other independently, and the
   draft is explicit about this (§13.12). Combining the two answers both questions: "is the caller
   allowed to call me?" and "is this exact operation what the user authorized?"

## PyTraT

I built [PyTraT](https://github.com/roshanlam/pytrat) to make this practical in Python. It
implements `draft-ietf-oauth-transaction-tokens-11` and ships as small packages:

| Package | What it does |
|---|---|
| `pytrat-core` | Claims, strict verifier, `tctx` binding, workload authentication, audit events |
| `pytrat-fastapi` / `pytrat-django` | Protect routes; forgotten routes fail closed |
| `pytrat-client` | Token exchange, and an HTTP client that forwards the token only to allowlisted hosts |
| `pytrat-server` | A reference Transaction Token Service |
| `pytrat-redis`, `pytrat-otel` | Replay protection across instances, OpenTelemetry export |

Protecting the ledger route in FastAPI looks like this:

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
    authenticator=WorkloadJwtAuthenticator(               # who is calling, independent of the token
        WorkloadKeys({"payment-service": StaticKeySet.from_jwks_file("payment-service.jwks.json")}),
        audience="ledger-service",
    ),
    protected_prefixes=("/internal",),                    # unprotected routes here fail closed
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

For each request, PyTraT reads exactly one `Txn-Token` header, verifies it, authenticates the
calling workload separately, checks scope, caller and the bound fields, and emits one audit event.
The handler runs only if everything passes.

## Running the attack

The repository has the whole chain as a runnable demo: an identity provider, the TTS, gateway,
payment service and ledger.

```bash
git clone https://github.com/roshanlam/pytrat && cd pytrat
uv sync --all-packages
uv run python examples/payment-transfer/demo.py
```

```text
── Transfer $100.00 from account-A to account-B (honest services)
✔ 201 recorded: 100.00 USD

── Transfer $100.00 from account-A to account-B (compromised payment service)
✘ 403 TRANSACTION_CONTEXT_MISMATCH: Transaction not authorized
ledger entries recorded: 0
```

The ledger's audit event names the check that failed (`'amount_minor': request value differs
from the authorized value`) but never logs the values or the token.

The same demo also runs as four containers under Docker Compose with verified TLS between every
service (`examples/payment-transfer/compose`).

## The details that make it hold

The idea is simple. Most of the work went into the details where a library like this usually
breaks.

**Comparison has to be strict.** If the token says `10000` and the body says `"10000"`, `10000.0`
or `true`, those are different values. Python's `==` disagrees (`True == 1`, `1 == 1.0`), so the
binding compares canonical values with exact types and refuses floats for amounts outright.

**The token must never choose its own trust.** Keys come from configuration, selected by `kid`.
`alg: none` and every `HS*` algorithm are rejected and cannot be enabled, so the classic
"HMAC-sign with the RSA public key" confusion is impossible. Headers that let a token point at its
own key (`jwk`, `jku`, `x5u`, `x5c`) are refused.

**Forgetting to protect a route should fail.** With `protected_prefixes`, a route under `/internal`
that does not declare `require_transaction` is denied by middleware, and a startup check reports it.

**Tokens stay out of logs.** Tokens live in a `SecretToken` wrapper whose `repr` is redacted. Audit
events carry a SHA-256 digest, never the token. The test suite has a fixture, applied to every
test, that fails any test whose log output contains something shaped like a JWT.

## What it does not do

Transaction Tokens are not encryption: anyone inside the trust domain can read `tctx`, so keep
personal data out of it. They are not replay-proof by design (the draft says so). PyTraT makes
single-use opt-in per route, with a Redis store when you run more than one instance. And they do
not help if the Transaction Token Service itself is compromised; that service is the root of trust.

Both specifications PyTraT implements are still Internet-Drafts, and the library is pre-1.0. It has
been reviewed adversarially and fuzzed, but not externally audited yet.

## Try it

```bash
pip install "pytrat[fastapi]"      # or [django], [client], [server], [all]
```

The [repository](https://github.com/roshanlam/pytrat) has the docs, the threat model, every
decision PyTraT made where the drafts are silent, and the demos. If you run services that pass
user intent through more than one hop, I would like to hear whether this fits how your system
works, and where it does not.

*Next: [what building a security library taught me](building-a-security-library.md), including the
binding bypass a fuzzer found in my own code.*
