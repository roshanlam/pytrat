# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses semantic versioning.

## [Unreleased]

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
