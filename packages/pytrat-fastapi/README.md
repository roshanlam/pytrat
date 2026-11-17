# pytrat-fastapi

FastAPI integration for PyTraT (OAuth Transaction Tokens): a
`require_transaction` dependency, fail-closed middleware for protected path prefixes, RFC 9457
problem responses, and transaction initiation at the edge.

```bash
pip install pytrat-fastapi
```

## Protect a route

```python
from typing import Annotated

from fastapi import Depends, FastAPI

from pytrat.core import StaticKeySet, TokenVerifier, VerifierSettings, WorkloadJwtAuthenticator, WorkloadKeys
from pytrat.fastapi import PyTraT, Transaction

pytrat = PyTraT(
    service="ledger-service",
    verifier=TokenVerifier(VerifierSettings(trust_domain="payments.internal"),
                           StaticKeySet.from_jwks_file("tts.jwks.json")),
    authenticator=WorkloadJwtAuthenticator(  # who is calling, independent of the token
        WorkloadKeys({"payment-service": StaticKeySet.from_jwks_file("payment-service.jwks.json")}),
        audience="ledger-service",
    ),
    protected_prefixes=("/internal",),  # forgotten routes fail closed
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
): ...  # only reached if the body matches the token's tctx exactly
```

Per request: exactly one `Txn-Token` header, signature/Trust Domain/lifetime verification, separate
workload authentication, scope, caller and strict typed `tctx` binding, one audit event, and the
token bound for outbound `AsyncTransactionClient` calls.

## Documentation

PyTraT documentation: *Getting started*, *FastAPI* and the `pytrat.fastapi` API reference (sources
in `docs/` of the repository).

Apache-2.0.
