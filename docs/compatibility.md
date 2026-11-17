# Protocol compatibility

PyTraT implements exactly these revisions. Both are Internet-Drafts and will change; PyTraT does not
claim conformance with any other revision.

| Specification | Revision | Status in PyTraT |
|---|---|---|
| OAuth Transaction Tokens | `draft-ietf-oauth-transaction-tokens-11` | Supported |
| Transaction Tokens for Agents | `draft-araut-oauth-transaction-tokens-for-agents-03` | Experimental (`pytrat-agents`) |
| OAuth 2.0 Token Exchange | RFC 8693 | Supported for Txn-Token issuance and replacement |
| JWT Profile for Client Authentication | RFC 7523 | Supported for workload authentication |

The vendored text of both drafts is in [`docs/spec/`](spec/). Programmatic access:
`pytrat.core.SUPPORTED_DRAFTS`.

## How to read the code

* `# txn-tokens-11 §N` and `# agent-profile-03 §N` comments mark normative rules. Each has a test
  whose docstring cites the same section (`tests/conformance/`).
* `# PyTraT profile:` comments mark choices made where the drafts are silent. They are listed below
  and are **not** protocol requirements; another conforming implementation may choose differently.

## PyTraT profile decisions

| # | Where the drafts are silent | PyTraT behaviour |
|---|---|---|
| P1 | No `alg` requirement (txn-tokens-11 §9.1) | Explicit allowlist. Default `ES256`, `EdDSA`, `PS256`; `RS*`, `PS384/512`, `ES384/512` opt-in. `none` and `HS*` are rejected unconditionally and cannot be enabled. Each key is bound to the algorithms of its key type. |
| P2 | No key distribution or discovery | Verifiers trust a JWKS from configuration (file, inline, or a pinned HTTPS URL). The reference TTS publishes `/.well-known/jwks.json`. `kid` is required by default. JOSE headers `jwk`, `jku`, `x5u`, `x5c`, `crit`, `b64` are rejected. |
| P3 | No numeric lifetime ("minutes or less", §6) | Verifiers reject `exp - iat` > 300 s by default and allow ≤ 60 s clock leeway (default 5 s). The reference TTS issues 60 s tokens by default. |
| P4 | No `subject_token_type` for replacement (§13.15) | `urn:ietf:params:oauth:token-type:txn_token`. |
| P5 | `req_wl` is one string in -11; agent-profile-03 §3.3.1 appends with commas and cites a base rule -11 does not contain | `req_wl` is stored verbatim. It is split on `,` only when `agentic_ctx` is present. Workload identifiers containing `,` are rejected by the TTS. |
| P6 | Agent draft compares assurance against the new agent (§3.3.1) *and* against the incoming token (§5.9); absent value unspecified | New value = `min(existing, agent level)`; an absent existing value counts as the deployment's lowest level, so the result never exceeds either reading. |
| P7 | `iss` is optional (§9.2) | When a verifier is configured with `expected_issuer`, `iss` becomes required and must match. |
| P8 | Replay protection "may not be feasible" (§13.2) | Opt-in per route (`single_use`). Records `(txn, operation)` until the token expires. In-memory store is per-process; multi-instance deployments need a shared store. |
| P9 | Call-chain maintenance mechanism unspecified (§13.15) | The TTS persists every issuance and replacement event, keyed by `txn`, in a hash-chained audit log. Chains are reconstructed from the log, not from the token. |
| P10 | Duplicate JSON member names | Rejected in JOSE headers, JWT payloads, JWKS documents and token-exchange responses. |
| P11 | `aud` may be an array under RFC 7519 | A Txn-Token is valid in exactly one Trust Domain, so an array `aud` is rejected. |
| P12 | Nested member missing inside a present claim | Reported as `CLAIM_INVALID` (the claim is present but malformed), not `CLAIM_MISSING`. |

## Known deviations and gaps

* Discovery metadata for the TTS is not defined by the draft and is not implemented.
* Cross-trust-domain flows (txn-tokens-11 §14, identity chaining) are out of scope.
* `unsigned_json` subject tokens (§11.2.2) are supported by the reference TTS but disabled by default.
