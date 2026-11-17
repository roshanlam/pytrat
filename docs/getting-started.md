# Getting started

This page takes you from nothing to a FastAPI route that only executes the exact operation a
Transaction Token authorized, with a test that proves it.

## Requirements

* Python 3.12 or later.
* The packages are published separately; install only what a service needs.

=== "uv"

    ```bash
    uv add pytrat-fastapi          # resource services (pulls in core, policy and client)
    uv add pytrat-cli              # developer tooling: keys, policy check, token inspect, TTS
    ```

=== "pip"

    ```bash
    pip install pytrat-fastapi
    pip install pytrat-cli
    ```

| You are building | Install |
|---|---|
| A FastAPI service that receives Txn-Tokens | `pytrat-fastapi` |
| A Django service that receives Txn-Tokens | `pytrat-django` |
| A service or job that only obtains or forwards tokens | `pytrat-client` |
| The Transaction Token Service | `pytrat-server` (reference implementation) |
| Verification only, in another framework | `pytrat-core` (+ `pytrat-policy` for the pipeline) |

## The 30-second demo

From a clone of the repository:

```bash
uv sync --all-packages
uv run python examples/payment-transfer/demo.py
```

The demo runs an API gateway, a payment service, a ledger and the reference TTS in-process. A user
transfers $100; then a compromised payment service rewrites the amount to $9,000 and the ledger
refuses with `403 TRANSACTION_CONTEXT_MISMATCH`, recording one audit event. Run
`examples/payment-transfer/serve.py` to see the same services on real sockets.

## Protect your first route

### 1. Generate keys

In production the TTS holds the signing key and resource services receive only its public JWKS.
For development, `pytrat keys generate` writes a private key (mode `0600`) and the matching public
JWKS:

```bash
pytrat keys generate --kid tts-2026-11 --out keys/        # the TTS signing key
pytrat keys generate --kid payment-service --out keys/    # the calling workload's key
```

```text
private key: keys/tts-2026-11.pem (mode 0600)
public JWKS: keys/tts-2026-11.jwks.json
private key: keys/payment-service.pem (mode 0600)
public JWKS: keys/payment-service.jwks.json
```

The ledger only ever reads the two `*.jwks.json` files. The `.pem` files belong to the TTS and to
the payment service respectively; never ship them to the ledger.

### 2. Write the service

```python title="ledger/app.py"
--8<-- "docs/snippets/first_route.py"
```

What this declares:

* **Trusted keys and algorithms** come from configuration (`tts_keys`, `ES256`). A token cannot
  supply its own key, and `none`/`HS*` can never be enabled.
* **Workload identity** is separate from the token: `WorkloadJwtAuthenticator` verifies a signed
  workload JWT in the `Workload-Identity` header, and the caller *is* the owner of the verifying
  key. Only `payment-service` may call this route.
* **Binding**: `source_account`, `destination_account`, `amount_minor` and `currency` in the
  validated body must equal the same members of the token's `tctx`, with exact types.
* **Fail closed**: `protected_prefixes=("/internal",)` makes the middleware deny any route under
  `/internal` that neither uses `require_transaction` nor is marked `@pytrat.exempt`, and
  `pytrat.lifespan` refuses to start if such a route exists.

Run it with any ASGI server, for example
`uvicorn --factory ledger.app:production_app`.

### 3. Test it

In tests, `pytrat.core.testing.TokenFactory` stands in for the TTS: it generates its own key and
mints valid (or deliberately broken) tokens. It is test-only and is never imported by production
code.

```python title="tests/test_ledger.py"
--8<-- "docs/snippets/try_first_route.py"
```

Every denial is an [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) problem document with a
stable `reason_code`; see [Errors and reason codes](guides/errors.md).

!!! tip "Both snippets on this page are tested"
    The code above is included verbatim from `docs/snippets/`, type-checked by `mypy --strict`
    and executed by `tests/docs/` on every CI run.

## Next steps

* Get real tokens: run the [reference TTS](guides/tts.md) and obtain tokens at the edge with the
  [client](guides/client.md) (or `initiate_transaction` in [FastAPI](guides/fastapi.md#initiating-a-transaction-at-the-edge)).
* Move route rules into a reviewed [YAML policy](guides/policies.md).
* Read the [Concepts](concepts.md) page before deploying: workload identity and replacement are
  easy to get wrong.
