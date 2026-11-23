# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses semantic versioning.

## [Unreleased]

### Added

- `pytrat demo`: the payment-transfer story ($100 recorded, a compromised service's $9,000
  refused) runs straight after `pip install "pytrat[all]"`, with no clone. `pytrat-cli` now depends
  on `pytrat-fastapi`, and the scenario moved from `examples/payment-transfer/payment_demo` into
  the CLI package, where the examples reuse it.
- `pytrat init`: writes a runnable starter project (development keys, a reference-TTS config, a
  protected FastAPI service, its tests and a gateway script).
- pytest plugin (`pytrat-core`, auto-registered): the `pytrat_kit` fixture stands in for the TTS
  and calling workloads, building `Txn-Token` and workload-JWT headers from in-memory keys.
  `pytrat_trust_domain` sets its Trust Domain. `pytrat.core.testing` is now a package.
- Documentation site configuration for Read the Docs (`.readthedocs.yaml`), and a Testing guide.

## [0.1.0] - 2026-11-17

### Added

- `pytrat-core`: Transaction Token claims, strict verifier (`verify_jws`/`TokenVerifier`), scopes,
  typed `tctx` binding, workload authenticators, replay store, audit events, RFC 9457 problem
  documents and test helpers, targeting `draft-ietf-oauth-transaction-tokens-11`.
- `pytrat-policy`: strict YAML policy model, compiler, route matching and `TransactionEnforcer`.
- `pytrat-client`: sans-IO RFC 8693 exchange with sync/async shells, RFC 7523 / mTLS / SPIFFE
  credentials, `WorkloadJwtAuth`, propagating HTTP clients, JWKS refresh.
- `pytrat-fastapi` and `pytrat-django`: framework integrations with fail-closed route coverage.
- `pytrat-server`: reference Transaction Token Service with issuance policy, replacement, key
  rotation, rate limiting and a hash-chained SQLite issuance log.
- `pytrat-agents` (experimental): `draft-araut-oauth-transaction-tokens-for-agents-03` profile.
- `pytrat-cli`: key generation, JWKS export, policy checks, token inspection, TTS runner.
- Examples: payment-transfer demo (in-process and real sockets) and agent delegation, run in CI.
- `pytrat-redis`: Redis replay store for multi-instance single use (atomic `SET NX PX`,
  per-service `namespace`, forced TLS verification, `verify_configuration()` for `noeviction`).
- `pytrat-otel`: `OpenTelemetryAuditSink` (span events and `pytrat.*.decisions` counters; never
  exports tokens or subjects).
- Docker Compose deployment of the payment demo with verified TLS on every hop.
- Atheris harnesses for every untrusted-input parser (nightly CI), failure-injection suite,
  Tokenetes interoperability report and tests, mkdocs documentation site, benchmark report.

### Fixed

- Context binding: object keys colliding after NFC normalisation could bypass binding.
- Single-use records now outlive the verifier's `exp` leeway (replay window of up to 60 s).
- Strict JSON rejects `1e400`, lone surrogates and excessive nesting; deep claims are `CLAIM_INVALID`.
- A failing audit sink keeps a denial's reason at resources and refuses unaudited grants (503);
  at the TTS the issuance log is authoritative.
- YAML loaders report every parse failure as `ConfigurationError`.
