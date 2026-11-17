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

## Run it with Docker Compose, over TLS

`compose/` deploys the same four services as separate containers. Containers do not share
loopback, so every hop uses HTTPS with certificate and host-name verification; PyTraT refuses
`http://` anywhere but loopback.

```bash
cd examples/payment-transfer/compose
docker compose up --build -d --wait          # init, then tts / ledger / payment / gateway
docker compose run --rm client               # the user transfers $100   -> 201

export PYTRAT_DEMO_COMPROMISED=1             # keep set for the next two commands
docker compose up -d --wait payment          # swap in the tampering payment service
docker compose run --rm client               # $100 rewritten to $9,000  -> 403
docker compose logs ledger | grep authorization.denied   # reason TRANSACTION_CONTEXT_MISMATCH

docker compose down -v; unset PYTRAT_DEMO_COMPROMISED     # destroys all generated key material
```

`python compose/smoke.py` does all of that with assertions and tears down afterwards; CI runs it
as `PYTRAT_TEST_COMPOSE=1 uv run pytest tests/integration/test_payment_compose.py`.

How it is wired:

* **One image** (`compose/Dockerfile`): a uv build stage installs only `pytrat-server` and
  `pytrat-fastapi` from the lockfile (`uv sync --frozen --no-dev --no-editable`); the runtime stage
  is `python:3.12-slim` with that virtualenv and `payment_demo/`, running as uid 10001.
  Containers run with a read-only root filesystem, a small `/tmp` tmpfs, all capabilities dropped
  and `no-new-privileges`. `compose/Dockerfile.dockerignore` limits the repository-root build
  context to the lockfile, `packages/` and `payment_demo/`.
* **`init`** (one-shot, `payment_demo/pki.py`) generates an ephemeral demo CA, a TLS certificate per
  service (SAN = compose service name; the gateway's also covers `localhost`/`127.0.0.1`), the ES256
  JWT keys and their public JWKS. The CA's private key is never written: once `init` exits nothing
  can issue another certificate for the deployment. The CA certificate carries name constraints for
  the demo's service names only. Material is generated once per volume lifetime, so restarting
  `init` never swaps keys under running services.
* **Volumes:** `public` (CA certificate and JWKS, mounted read-only everywhere) and one private
  volume per container, so each process holds only its own private keys (0600):

  | Container | Private volume holds |
  |---|---|
  | `tts` | TLS key/cert, `tts.pem` (Txn-Token signing key) |
  | `gateway` | TLS key/cert, `api-gateway.pem` (workload key) |
  | `payment` | TLS key/cert, `payment-service.pem` (workload key) |
  | `ledger` | TLS key/cert |
  | `client` | `idp.pem` (stands in for the identity provider that logs the user in) |

* **Trust:** `payment_demo/container.py` builds a `Lab` from environment variables
  (`PYTRAT_DEMO_*_URL`, which must be `https://`) with `Lab.load(..., ca_bundle=...)`. Every outbound
  httpx client in `services.py` verifies against an `ssl.SSLContext` that trusts *only* the demo CA.
  The outbound allowlists are the same `https://<service>:8443` origins.
* **Services:** each runs `uvicorn payment_demo.container:<service>_app --factory` with
  `--ssl-keyfile/--ssl-certfile`; healthchecks make a verified HTTPS request. Only the gateway is
  published, on `127.0.0.1:8443` (override with `PYTRAT_DEMO_GATEWAY_PORT`). Audit events go to
  stdout as JSON lines.

## Files

* `payment_demo/lab.py`: key generation and the TTS configuration (issuance policy allowlists
  exactly the four transfer fields into `tctx`).
* `payment_demo/services.py`: the four FastAPI apps.
* `payment_demo/scenario.py`: in-process deployment with a host-routing ASGI transport.
* `payment_demo/pki.py`, `payment_demo/container.py`: key/certificate generation and the
  environment-driven entrypoint for the Compose deployment.
* `compose/`: `Dockerfile`, `Dockerfile.dockerignore`, `compose.yaml` and `smoke.py`.
