# Errors and reason codes

Every error PyTraT raises derives from `pytrat.core.PyTraTError` and carries a stable
`ReasonCode`. **Reason codes are public API**: new codes may be added; existing codes are never
renamed or removed. Match on `error.reason`, not on messages.

Error `detail` strings name the check that failed. They never contain tokens, key material or the
values being compared, so they are safe to log.

## Error classes

| Class | HTTP status | Raised when |
|---|---|---|
| `TokenError` | 401 | The token is missing, malformed, untrusted or not currently valid. |
| `AuthenticationError` | 401 | The calling workload (or the subject token at the edge) could not be authenticated. Distinct from `TokenError` because a Txn-Token is never an authentication credential. |
| `AuthorizationError` | 403 | The token is valid but does not authorize this operation. |
| `RequestError` | 400 | The request's own data is malformed or ambiguous. The FastAPI integration uses 422 (`MalformedRequestError`). |
| `ConfigurationError` | 500 | Configuration is invalid. Raised at startup, never on the request path. |
| `DependencyError` | 503 | A dependency needed for the decision is unavailable. The decision is *deny*. |
| `pytrat.client.ExchangeError` | 502 | A token exchange was refused or the TTS response did not conform. |
| `pytrat.server.OAuthError` | per RFC 6749 | A token-endpoint rejection at the TTS. |
| `pytrat.agents.ToolArgumentError` / `ToolResultBlockedError` | 400 / 500 | The tool runtime refused model-supplied arguments or a tool result. |

## Reason codes

This table is generated from `pytrat.core.ReasonCode` when the site is built; the build fails if a
code is undocumented.

<!-- pytrat:reason-codes -->

## Problem responses

The FastAPI and Django integrations render every `PyTraTError` as an RFC 9457 problem document,
built by the shared `pytrat.core.problem_details`:

```json
{
  "type": "urn:pytrat:problem:SCOPE_INSUFFICIENT",
  "title": "Transaction not authorized",
  "status": 403,
  "reason_code": "SCOPE_INSUFFICIENT",
  "transaction_id": "01a1e862-…"
}
```

* `type` is `urn:pytrat:problem:<REASON_CODE>`; `title` is fixed per error class.
* `transaction_id` is present only after the token was verified, never from unverified input.
* `detail` is omitted unless debug errors are enabled (`PyTraT(debug=True)`,
  `PYTRAT["DEBUG_ERRORS"] = True`), to minimise what an attacker learns.

## Token endpoint

The reference TTS answers with RFC 6749 §5.2 errors and records the PyTraT reason code in the audit
log and the issuance log:

| `error` | Status | Typical reason codes |
|---|---|---|
| `invalid_request` | 400 | `TOKEN_MALFORMED`, `CLAIM_MISSING`, `CLAIM_INVALID` |
| `unsupported_grant_type` | 400 | `TOKEN_TYPE_INVALID` |
| `invalid_client` | 401 | `WORKLOAD_UNAUTHENTICATED`, `REPLAY_DETECTED` (reused assertion `jti`) |
| `invalid_grant` | 400 | `SUBJECT_TOKEN_INVALID`, `TOKEN_EXPIRED`, `REPLACEMENT_LIMIT_EXCEEDED` |
| `unauthorized_client` | 400 | `ISSUANCE_NOT_AUTHORIZED` |
| `invalid_scope` | 400 | `SCOPE_INSUFFICIENT`, `REPLACEMENT_WIDENS_AUTHORIZATION` |
| `invalid_target` | 400 | `TRUST_DOMAIN_MISMATCH` (requested audience is not the Trust Domain) |
| `slow_down` | 429 | `RATE_LIMITED` |
| `temporarily_unavailable` | 503 | `DEPENDENCY_UNAVAILABLE` |
| `server_error` | 500 | unexpected internal failure (nothing internal is returned) |

`pytrat.client` surfaces these as `ExchangeError` with the sanitised `oauth_error` and
`oauth_error_description`.
