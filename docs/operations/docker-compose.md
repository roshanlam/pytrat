# Deploying with Docker Compose

`examples/payment-transfer/compose/` runs the four demo services (TTS, gateway, payment, ledger) as
separate containers, with **verified TLS on every hop**:

* A one-shot `init` container generates a demo CA, whose private key is never written to disk, so
  nothing can issue further certificates. The CA is name-constrained to the compose service names.
* `init` also issues one TLS certificate per service, and the TTS and workload signing keys with
  their JWKS.
* Each service mounts only its own private volume (keys 0600). The shared volume holds only public
  material (CA certificate, JWKS) and is mounted read-only.
* Outbound clients trust only the demo CA and check hostnames. The `Txn-Token` allowlist contains
  only `https://<service>:8443` origins.
* Containers run as a non-root user with a read-only root filesystem, `cap_drop: ALL` and
  `no-new-privileges`. Only the gateway is published, on `127.0.0.1:8443`.

```bash
cd examples/payment-transfer/compose
docker compose up --build -d --wait
docker compose run --rm client                    # honest $100 transfer: 201

export PYTRAT_DEMO_COMPROMISED=1                  # payment service rewrites the amount
docker compose up -d --wait payment
docker compose run --rm client                    # 403 TRANSACTION_CONTEXT_MISMATCH
docker compose logs ledger | grep authorization.denied

docker compose down -v; unset PYTRAT_DEMO_COMPROMISED
```

`python examples/payment-transfer/compose/smoke.py` runs the whole sequence with assertions and
tears the stack down. CI runs it via `PYTRAT_TEST_COMPOSE=1 pytest
tests/integration/test_payment_compose.py`.

!!! warning "A demo, not a production deployment"
    The CA and keys are generated per volume for demonstration. In production, issue workload
    certificates from your real PKI or SPIFFE, keep the TTS signing key in a KMS/HSM where possible,
    and keep the Redis replay store (if used) and the issuance log on durable storage.

See `examples/payment-transfer/README.md` in the repository for the full walkthrough.
