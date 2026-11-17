# Protocol compatibility

PyTraT implements exactly these revisions. Both are Internet-Drafts and will change; PyTraT does not
claim conformance with any other revision.

| Specification | Revision | Status in PyTraT |
|---|---|---|
| OAuth Transaction Tokens | `draft-ietf-oauth-transaction-tokens-11` | Supported |
| Transaction Tokens for Agents | `draft-araut-oauth-transaction-tokens-for-agents-03` | Experimental (`pytrat-agents`) |
| OAuth 2.0 Token Exchange | RFC 8693 | Supported for Txn-Token issuance and replacement |
| JWT Profile for Client Authentication | RFC 7523 | Supported for workload authentication |

The vendored text of both drafts is in `docs/spec/`
([base draft](spec/draft-ietf-oauth-transaction-tokens-11.txt),
[agent draft](spec/draft-araut-oauth-transaction-tokens-for-agents-03.txt)). Programmatic access:
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
| P8 | Replay protection "may not be feasible" (§13.2) | Opt-in per route (`single_use`). Records `(txn, operation)` until `exp` plus the maximum verifier leeway (60 s), so a token still accepted inside the leeway window cannot be reused. In-memory store is per-process; multi-instance deployments use `pytrat-redis` (P31). |
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
| P23 | Reference TTS request surface | `client_secret` (symmetric client auth), `actor_token` and `resource` parameters are refused; duplicate form parameters are rejected. |
| P24 | Issuance-policy context allowlists | `request_details` → `tctx` and `request_context` → `rctx` copy only allowlisted members; unlisted members are dropped (names audited). An allowlisted member with the wrong JSON type rejects the request rather than being dropped. Floats are disallowed by default. |
| P25 | Subject tokens (§11.2) | `self_signed` and `unsigned_json` are disabled by default. A subject without a known scope is rejected (§13.6, §13.14). Client-credentials subjects are detected by `gty=client-credentials` or `sub == client_id`. Subject and replacement-input expiry (§6, §13.15) are checked with zero leeway. |
| P26 | Txn-Token lifetime vs subject lifetime (§6 leaves it to policy) | `exp` is capped at the subject token's `exp` by default. On replacement, `exp` is capped at the input token's `exp` unless `extend_lifetime` is enabled, in which case `max_replacements_per_txn` applies. |
| P27 | `act` when the agent profile is disabled | Copied unchanged from the subject token (RFC 8693 semantics); `agentic_ctx` on an input token is carried forward unmodified. |
| P28 | `act` in self-signed (§11.2.1) or unsigned (§11.2.2) subjects | Refused (`ISSUANCE_NOT_AUTHORIZED`): such subjects are written by the requesting workload, which must not be able to name an agent (and inherit its assurance). Delegation must come from an independent issuer's token. |
| P29 | Workload JWT identity at resource services | The caller is the *owner* of the verifying key (`WorkloadKeys`); `sub` and `iss` (if present) must name that owner. A workload can never authenticate as another workload, even with a valid signature. |
| P30 | Resource agent constraints on a token without `agentic_ctx` | `minimum_assurance`, `allowed_originators`, `require_verified_agent` and `require_agent_context` deny (`AGENT_CONTEXT_MISSING`); a `maximum_hops` limit alone accepts it (zero agent hops). |
| P31 | Replay storage across instances (§13.1–§13.2 silent) | `pytrat-redis`: one atomic `SET key 1 NX PX ttl` per first use. Keys are `prefix + namespace + ":" + SHA-256(replay key)`, so raw `txn` values are never stored. `namespace` is required and names the service, so services sharing one Redis never share records and a token cannot be pre-burned at another service. The TTL is relative, computed from PyTraT's clock rather than Redis's, plus a retention margin (default 60 s). Non-finite expiries, expiries more than `max_ttl` ahead (1 h) and already-past expiries are refused, never truncated. Every Redis error, timeout or unexpected reply is `DEPENDENCY_UNAVAILABLE` (deny). There are no client retries. Redis **must** run `maxmemory-policy noeviction`, because eviction silently re-enables replay; `verify_configuration()` checks this at startup. Records lost to a non-persistent restart or an asynchronous-replica failover re-open replay until the token expires; use AOF. For `rediss://`, certificate and hostname verification are forced on, and a URL that disables either is refused. |
| P32 | Audit telemetry (not in the drafts) | `pytrat-otel` exports each audit event as a span event named `pytrat.<event_type>`, with `pytrat.*` attributes that are stable and add-only, plus `pytrat.{authorization,issuance,replacement}.decisions` counters. `subject` is never exported. Any token-shaped string attribute is dropped and counted. When no span is recording, a short `pytrat.audit` span carries the event. |
| P33 | Nesting depth of untrusted JSON (not in the drafts) | `strict_loads` refuses deeply nested documents and non-finite numbers such as `1e400`. Claim values (`tctx`, `rctx`, `act`, ...) deeper than 64 levels are `CLAIM_INVALID`. Bound values deeper than 32 levels are refused. |
| P34 | Object keys that collide after Unicode NFC normalisation | Rejected: `TRANSACTION_CONTEXT_MISMATCH` in request data, `CLAIM_INVALID` in `tctx`. Otherwise one spelling could pass binding while the service reads the other. |
| P35 | Audit sink failure | At a resource the sink is the only audit record: a denial keeps its own reason code, and a grant that cannot be audited is refused with `DEPENDENCY_UNAVAILABLE` (503). A single-use grant refused this way has already consumed its use, so it is not retryable with the same token (fail closed). At the TTS the hash-chained issuance log is authoritative: an issuance it has recorded is released even if the secondary sink fails (the failure is logged). If the log itself cannot record it, the token is withheld (503). |
| P36 | Lone surrogates in JSON (not in the drafts) | Rejected by `strict_loads` everywhere: Txn-Token payloads, JWKS documents, TTS `request_details`/`request_context` and exchange responses (I-JSON, RFC 7493 §2.1). |

The full reconciliation of the agent draft, with section references and every ambiguity, is in
[`docs/spec/agent-profile-03-notes.md`](spec/agent-profile-03-notes.md).

## Known deviations and gaps

* When a JWKS endpoint has been unreachable for longer than `max_stale`, resource services deny
  with 401 `KEY_UNKNOWN` (audited as `token.rejected`) rather than 503: the key lookup fails
  closed inside verification, so the request is audited like any other unverifiable token.

* Discovery metadata for the TTS is not defined by the draft and is not implemented.
* Cross-trust-domain flows (txn-tokens-11 §14, identity chaining) are out of scope.
* `unsigned_json` subject tokens (§11.2.2) are supported by the reference TTS but disabled by default.
* The reference TTS rate-limits per *authenticated* workload. Unauthenticated floods are bounded only
  by request-size limits; put the TTS behind an ingress rate limiter in production.
