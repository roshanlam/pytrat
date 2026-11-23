# Testing

Testing a protected route needs two things the real system gets from elsewhere: a Transaction
Token signed by a key the service trusts, and proof of which workload is calling. Installing
`pytrat` installs a pytest plugin that provides both, so your tests need no TTS, no key files and
no network.

## The `pytrat_kit` fixture

`pytrat_kit` is a `TransactionTestKit`, created fresh for each test with its own in-memory keys.

| Method | Returns |
|---|---|
| `tts_keys()` | The keys your service must trust to verify the kit's tokens. Pass them where production code passes the TTS's JWKS. |
| `workload_keys(*ids)` | A `WorkloadKeys` registry for the named calling workloads, for `WorkloadJwtAuthenticator`. |
| `headers(scope=..., tctx=..., caller=..., audience=...)` | Request headers carrying a valid `Txn-Token` and, when `caller` is given, a workload JWT addressed to `audience` (the service's name). |
| `token(scope=..., tctx=..., **claims)` | Just the signed token. Any claim can be overridden; a value of `None` removes the claim. |
| `workload_jwt(caller, audience=...)` | Just the workload credential. |
| `verifier()` | A `TokenVerifier` that trusts the kit, for testing code that verifies tokens directly. |
| `factory` | The underlying [`TokenFactory`](../api/core.md), for deliberately broken tokens (`unsigned()`, `hmac_with_public_key()`, …). |

Tokens are issued at the current time, so the service under test needs no special clock.

The kit mints tokens for the Trust Domain `example.internal`. Override the `pytrat_trust_domain`
fixture, in a test module or a `conftest.py`, to match your service:

```python
@pytest.fixture
def pytrat_trust_domain() -> str:
    return "payments.internal"
```

## A complete example

The [getting-started](../getting-started.md) service, tested for the honest request, a tampered
amount and a missing caller:

```python title="tests/test_ledger.py"
--8<-- "docs/snippets/try_first_route.py"
```

Test the refusals too, and assert the specific `reason_code`, not just the status: a `403` for the
wrong reason means a check you rely on is not the one that fired. Useful cases:

| Request | Expected `reason_code` |
|---|---|
| No `Txn-Token` header | `TOKEN_MISSING` |
| Body differs from `tctx` | `TRANSACTION_CONTEXT_MISMATCH` |
| `scope` the route does not accept | `SCOPE_INSUFFICIENT` |
| `caller` not in `allowed_callers` | `CALLER_NOT_ALLOWED` |
| No `caller` (no workload credential) | `WORKLOAD_UNAUTHENTICATED` |
| `pytrat_kit.token(scope=..., iat=now - 180, exp=now - 120)` | `TOKEN_EXPIRED` |

## Without pytest's plugin discovery

If plugin autoloading is disabled (`PYTEST_DISABLE_PLUGIN_AUTOLOAD`), load it explicitly in your
top-level `conftest.py`:

```python
pytest_plugins = ["pytrat.core.testing.pytest_plugin"]
```

Outside pytest, construct the kit directly: `TransactionTestKit(trust_domain="payments.internal")`.

!!! warning "Test code only"
    Everything in `pytrat.core.testing` signs tokens with throwaway keys. Never import it from
    production code; an import-linter contract enforces this inside PyTraT itself.
