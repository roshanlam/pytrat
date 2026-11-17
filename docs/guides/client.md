# Client and propagation

`pytrat-client` is everything a workload needs on the *outbound* side: obtaining Txn-Tokens from
the TTS (RFC 8693), authenticating to it and to other workloads, forwarding the current token, and
keeping the TTS's public keys fresh. Every class has a sync and an async variant that share the
same pure logic.

```bash
uv add pytrat-client
```

| Async | Sync | Purpose |
|---|---|---|
| `AsyncTransactionTokenClient` | `TransactionTokenClient` | Token exchange: `issue()` and `replace()`. |
| `AsyncTransactionClient` | `TransactionClient` | HTTP client that forwards the bound token to allowlisted origins. |
| `AsyncJwksRefresher` | `JwksRefresher` | Keeps the TTS's JWKS fresh for a `TokenVerifier`. |
| `WorkloadJwtAuth` | (same) | `httpx.Auth` that signs a workload JWT per request. |

The examples below are one module, `client_usage.py`, exercised against the real reference TTS
by the documentation tests.

## Trusting the TTS's keys

```python
--8<-- "docs/snippets/client_usage.py:verifier"
```

Call `await jwks.refresh()` at startup (the FastAPI integration does this when you pass
`jwks_refresher=`). The URL must be HTTPS; `allow_insecure_localhost=True` permits plain HTTP to
loopback addresses for development only. Responses larger than 256 KiB, duplicate JSON members and
an empty key set count as a failed refresh.

## Obtaining a token (exchange)

```python
--8<-- "docs/snippets/client_usage.py:exchange"
```

* **Workload credentials.** `PrivateKeyJwtCredential` signs a fresh RFC 7523 assertion (≤ 60 s,
  unique `jti`) for every request; the private key is read once from a file, never accepted as an
  inline string. Alternatives: `MtlsCredential(cert_path, key_path, client_id=...)` for mutual TLS
  and `SpiffeJwtSvidCredential(svid_path, client_id)` for a SPIFFE JWT-SVID file that is re-read
  on every request.
* **Subject tokens** are `SecretToken`s. Refresh tokens are refused before any I/O
  (`SUBJECT_TOKEN_INVALID`).
* **Verification.** The issued token is verified locally with your `TokenVerifier` before it is
  returned. A refusal from the TTS raises `ExchangeError` (`EXCHANGE_FAILED`, HTTP 502 at your
  edge) with the sanitised OAuth `error` code; anything token-shaped in the TTS's error text is
  redacted. A network failure raises `DependencyError` (`DEPENDENCY_UNAVAILABLE`).
* **Response limits.** Success responses must be `application/json` and at most 64 KiB (P13).

## Replacing a token

```python
--8<-- "docs/snippets/client_usage.py:replace"
```

A workload needs `may_replace: true` in the TTS issuance policy to do this. The client enforces
attenuation on both sides of the exchange: a requested scope that is not a subset of the current
one is refused before any I/O, and a reply that changed `txn`, `sub`, `aud`, `act` or the agent
originator, widened the scope or lowered `hop_count` is rejected
(`REPLACEMENT_WIDENS_AUTHORIZATION`).

## Forwarding the token (propagation)

```python
--8<-- "docs/snippets/client_usage.py:propagate"
```

The propagating client enforces the outbound rules (P16):

* **Exact-origin allowlist.** `trusted_destinations` lists `scheme://host[:port]` origins. A
  request to anything else fails with `DESTINATION_NOT_TRUSTED` **before connecting**, and the
  allowlist is re-checked for every request an auth flow yields.
* **No redirects.** Redirect responses are returned to you, never followed with the token.
* **Never `Authorization`.** The token travels only in `Txn-Token`. Setting a `Txn-Token` header
  yourself is a `ConfigurationError`, and an auth flow that puts the token in `Authorization` is
  refused.
* **A transaction is required by default.** Without a bound token the call fails with
  `TOKEN_MISSING`; pass `require_transaction=False` for calls that may legitimately run outside a
  transaction (the token is still attached if one is bound).
* **HTTPS only**, except loopback with `allow_insecure_localhost=True`.

Inside a FastAPI handler protected by `require_transaction`, or a Django view decorated with
`@require_transaction`, the verified token is already bound for the duration of the request. In
background jobs, bind it yourself with `bind_transaction(token)`; `current_transaction()` returns
the bound token (or raises `TOKEN_MISSING`) and `optional_transaction()` returns it or `None`.

### Replacing on the way out

Pass `replacer=` (a `Replacer` / `AsyncReplacer`, i.e. a function from `VerifiedToken` to
`VerifiedToken`) to obtain a narrower token before each outbound call, for example
`lambda token: tts.replace(token, Scope.parse("ledger.write"))`.

## Workload identity for outbound calls

`WorkloadJwtAuth` authenticates this workload to the destination, which verifies it with
`WorkloadJwtAuthenticator` (see [Concepts](../concepts.md#workload-identity-is-not-the-txn-token)):

| Argument | Meaning |
|---|---|
| `workload_id` | This workload's identifier, the JWT `sub`. |
| `private_key_path` | PEM private key file (never an inline string). |
| `kid`, `alg` | Key id published in the receivers' trusted workload key set, and its algorithm. |
| `audiences` | Destination origin → the audience that destination expects. Requests to any other origin are refused. |
| `lifetime` | JWT lifetime in seconds (default 60, at most 300). |
| `header` | Header name (default `Workload-Identity`). |

## Low-level building blocks

`build_issue_request`, `build_replacement_request`, `parse_exchange_response` and
`check_replacement` are the pure functions the clients are made of; use them to integrate with a
different HTTP stack. `verify_with_refresh` / `verify_with_refresh_async` verify a token and
retry once after a forced JWKS refresh when the `kid` is unknown.
