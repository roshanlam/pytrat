# Payment-transfer demo

The PyTraT v0.1 security story: a user transfers **$100**; a compromised payment service tries to
make it **$9,000**; the ledger refuses and records why.

```text
user ──► api-gateway ──► payment-service ──► ledger-service
              │
              └──► TTS (RFC 8693 token exchange)
```

| Service | Role |
|---|---|
| `api-gateway` | Trusted edge. Validates the transfer, exchanges the user's access token for a Txn-Token whose `tctx` records the authorized transfer. |
| `payment-service` | Requires a transaction from `api-gateway`; forwards the transfer and the **unchanged** Txn-Token to the ledger. In the compromised run it rewrites the amount. |
| `ledger-service` | Requires a transaction from `payment-service` and binds the body to `tctx`. |
| TTS | The reference `pytrat-server`, issuing 60-second ES256 tokens. |

Every internal hop also authenticates the calling workload with a signed workload JWT, because a
Txn-Token is never an authentication credential.

## Run it

```bash
uv run python examples/payment-transfer/demo.py    # in-process over ASGI, narrated
uv run python examples/payment-transfer/serve.py   # same services on real TCP sockets (127.0.0.1)
uv run python examples/payment-transfer/serve.py --keep-running   # leave the stack up
```

Keys are generated fresh into a temporary directory on every run; nothing secret is committed.
The same code runs in CI as `tests/integration/test_payment_demo.py`.

## Files

* `payment_demo/lab.py`: key generation and the TTS configuration (issuance policy allowlists
  exactly the four transfer fields into `tctx`).
* `payment_demo/services.py`: the four FastAPI apps.
* `payment_demo/scenario.py`: in-process deployment with a host-routing ASGI transport.
