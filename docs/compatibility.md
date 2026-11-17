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
| P13 | Client-side handling of exchange responses | Success responses must be `application/json` and ≤ 64 KiB; error text echoed by the TTS is redacted of anything token-shaped. Every issued token is verified locally before use, and a replacement is rejected client-side if it changed `txn`, `sub`, `aud`, `act` or the agent `originator`, widened scope, or lowered `hop_count`. |
| P14 | Transport security for the TTS and JWKS endpoints | HTTPS required; plain HTTP only for `localhost`/loopback when explicitly enabled for development. An empty JWKS counts as a failed refresh. |
| P15 | RFC 7523 client assertions | Lifetime ≤ 60 s from the client; the reference TTS accepts ≤ 5 min and enforces single-use `jti`. |
| P16 | Outbound propagation | Exact-origin allowlist checked before connecting and again on every request an auth flow yields; redirects never followed; the token is never placed in `Authorization`. |
| P17 | agent-profile-03 §4.2.3: whether "exceeds" refers to the incoming or resulting `hop_count` | The resulting count is checked on every replacement, including non-agent ones. |
| P18 | agent-profile-03 §3.5.1 vs §3.6.1 agent identification order | `act.sub` → Agent Attribute Store → `client_id`. If `act.sub` is unregistered and `client_id` resolves to a *different* agent, the request is denied (`AGENT_UNVERIFIED`). On replacement the requesting agent is identified from the requester's authenticated identity, never from the token's `act`. |
| P19 | agent-profile-03 §3.2.2: client-credentials tokens MUST NOT carry `act` | A subject token that violates this is rejected (`ISSUANCE_NOT_AUTHORIZED`), not silently stripped. |
| P20 | Agent replaces a token that has no `agentic_ctx` | Denied (`AGENT_CONTEXT_MISSING`) when `require_replacement` is on (default); otherwise a new chain starts with that agent as originator. |
| P21 | agent-profile-03 §5.13 egress stripping of "internal identifiers" | `strip_for_egress` removes `attr_store_ref`; the draft does not define other internal identifiers. |
| P22 | Trusted agent runtime | Tool arguments are validated before the tool runs; the tool never receives the token; results containing compact-JWS-shaped strings (or unscannable values) are blocked. Tools whose names or parameter types look like credential operations are refused at registration. |

The full reconciliation of the agent draft, with section references and every ambiguity, is in
[`docs/spec/agent-profile-03-notes.md`](spec/agent-profile-03-notes.md).

## Known deviations and gaps

* Discovery metadata for the TTS is not defined by the draft and is not implemented.
* Cross-trust-domain flows (txn-tokens-11 §14, identity chaining) are out of scope.
* `unsigned_json` subject tokens (§11.2.2) are supported by the reference TTS but disabled by default.
