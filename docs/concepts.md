# Concepts

Section references (`§`) are to `draft-ietf-oauth-transaction-tokens-11` unless noted. Where the
draft is silent, PyTraT made a choice; those are marked **PyTraT profile** and listed with numbers
(P1, P2, ...) in [Protocol compatibility](compatibility.md).

## Trust Domain

A Trust Domain is the set of workloads that trust one Transaction Token Service, for example
everything behind your API gateway in `payments.internal`. A Txn-Token is valid in exactly one
Trust Domain: its `aud` claim is the Trust Domain name, and a verifier configured with
`VerifierSettings(trust_domain="payments.internal")` rejects anything else
(`TRUST_DOMAIN_MISMATCH`). An array `aud` is rejected outright (P11).

Cross-domain flows (§14, identity chaining) are out of scope.

## Transaction Token Service (TTS)

The TTS is the only component that signs Transaction Tokens. A workload, usually the edge,
exchanges the caller's credential (an OAuth access token, or another subject token type) for a
Txn-Token with an RFC 8693 token exchange (§11). The TTS:

1. authenticates the requesting workload (RFC 7523 `private_key_jwt` or a trusted mTLS proxy);
2. validates the subject token against an issuer it trusts;
3. applies its **issuance policy**: which workloads may obtain which scopes, and which members of
   `request_details` and `request_context` become `tctx` and `rctx` (with required JSON types);
4. signs a short-lived token (60 s by default) and records the issuance in a hash-chained log.

Resource services never call the TTS to verify a token: they hold its public keys (a JWKS from
configuration or a pinned URL) and verify locally. See [Running the TTS](guides/tts.md).

!!! danger "Only the TTS signs"
    No other PyTraT package holds signing keys or constructs a signed Txn-Token. Test helpers that
    mint tokens live in `pytrat.core.testing` and are never imported by production code.

## Txn-Token claims

A Txn-Token is a JWS with `typ: txntoken+jwt` (§9.1), carried in the `Txn-Token` HTTP header
(§12.1), never in `Authorization`. `pytrat.core.TransactionClaims` is the parsed form.

| Claim | Meaning | In PyTraT |
|---|---|---|
| `aud` | The Trust Domain. | Required; exactly one string. |
| `txn` | Unique transaction identifier, stable across every hop and replacement. | Required. `Transaction.id`. |
| `sub` | The principal the transaction is for (the user, or a service). | Required. Never changes on replacement. |
| `scope` | What kind of operation is authorized (`payments.transfer`). | Required; parsed into `Scope`. |
| `req_wl` | The workload that requested the token. | Required; stored verbatim (P5). |
| `iat`, `exp` | Issue and expiry times. | Required; `exp - iat` ≤ 300 s by default (P3). |
| `iss` | The TTS. | Optional; required when `expected_issuer` is set (P7). |
| `tctx` | **Transaction context**: the authorized parameters (`amount_minor`, accounts, ...). | Optional JSON object; what [binding](#tctx-binding-and-strict-comparison) checks. |
| `rctx` | **Requester context**: facts about the original request (IP, channel, authentication). | Optional JSON object; informational. |
| `act` | RFC 8693 actor (delegation). | Optional; copied from the subject token (P27). |
| `agentic_ctx` | Agent chain (agent profile only). | Optional; see [Agents](guides/agents.md). |

Unknown claims are ignored, never rejected (§9.2). Claims are only ever read from a **verified**
token: `TokenVerifier.verify` returns a `VerifiedToken` (which cannot be constructed any other way)
or raises a `TokenError` with a specific reason.

## `tctx` binding and strict comparison

Verifying the signature proves the token is genuine. It does not prove the request you are about to
execute is the one the token authorized. **Binding** closes that gap: for each bound field, the
value in the request must equal the value in `tctx`. In FastAPI that is
`require_transaction(bind_fields=[...])`, in Django `@require_transaction(bind_fields=[...])`, in
YAML `bind_context: [...]`; all three compile to a `ContextBinding`, once, at startup.

Comparison is strict and canonical (`pytrat.core.binding`):

| Request value | `tctx` value | Result |
|---|---|---|
| `10000` | `10000` | equal |
| `"10000"` | `10000` | **mismatch**: different types |
| `True` | `1` | **mismatch**: `bool` is not `int` |
| `100.00` | anything | **unbindable**: floats are refused; use integer minor units |
| `"café"` (NFD) | `"café"` (NFC) | equal: strings are NFC-normalised, never trimmed or case-folded |
| absent | `10000` | **mismatch** (`TRANSACTION_CONTEXT_MISMATCH`) |
| `10000` | absent | **missing** (`TRANSACTION_CONTEXT_MISSING`) |

Objects compare key by key and lists element by element, recursively. A float inside `tctx` itself
makes the token unusable for binding (`CLAIM_INVALID`).

Bind against what the handler actually receives. The FastAPI integration reads path, query and
body fields through FastAPI's own validators, so the bound values *are* the handler's values. Use
strict Pydantic models (`ConfigDict(strict=True)`): a lax model coerces `"10000"` to `10000` before
binding sees it.

When a service legitimately transforms a value between hops, declare it with `Derived`; there is
no implicit coercion. A mapping binds differently named fields. The same specifications can be
passed as `bind_fields` to either framework integration:

```python
--8<-- "docs/snippets/binding.py"
```

## Workload identity is not the Txn-Token

> A Txn-Token is not an authentication credential. (§13.12)

The token says *what* was authorized. It never says *who is calling you*: a token captured from
one hop can be replayed by anyone who can reach the next. So every resource service authenticates
its immediate caller independently and checks it against `allowed_callers`:

* `WorkloadJwtAuthenticator`: a short-lived signed workload JWT in the `Workload-Identity` header,
  verified against `WorkloadKeys`. The caller **is the owner of the verifying key**; the JWT's
  `sub` must name that same workload, so one workload can never authenticate as another (P29).
  Callers sign these with `pytrat.client.WorkloadJwtAuth`.
* `TrustedProxyHeaderAuthenticator`: the identity a TLS-terminating proxy (mTLS, SPIFFE) puts in a
  header, honoured only when the TCP peer is a configured proxy address.
* `FirstMatchAuthenticator`: tries several in order.

Without an authenticator, every policy that requires workload identity (the default) denies with
`WORKLOAD_UNAUTHENTICATED`.

## Propagation

A service that calls the next hop forwards the token **unchanged** (§12.2).
`AsyncTransactionClient` / `TransactionClient` attach the bound token to requests, but only to
origins on an exact allowlist, checked before connecting; they never follow redirects and never
put the token in `Authorization`. Inside a protected FastAPI handler or Django view the verified
token is already bound. See [Client and propagation](guides/client.md).

## Replacement and attenuation

A workload that needs a token for a narrower purpose (fewer scopes, an added `rctx` member, an
agent hop) asks the TTS for a **replacement** (§13.15), presenting the current Txn-Token as the
subject token. Replacement only ever **attenuates**:

| Claim | On replacement |
|---|---|
| `txn`, `sub`, `aud`, `iss`, `tctx`, `act`, agent `originator` | never change |
| `scope` | may only shrink (requested ⊆ current) |
| `rctx` | may only gain members |
| `exp` | capped at the input token's `exp`, unless `replacement.extend_lifetime` is on (then limited by `max_replacements_per_txn`) |
| agent `min_assurance_level` | may only fall |
| agent `hop_count` | only rises; the result is checked against `max_hops` |

The client checks this too: `TransactionTokenClient.replace` refuses a widening scope before any
I/O and rejects a reply that changed an immutable claim (`REPLACEMENT_WIDENS_AUTHORIZATION`, P13).

## Audit

Every decision produces exactly one `AuditEvent`, delivered to an `AuditSink`:

| Event type | Emitted by |
|---|---|
| `authorization.granted`, `authorization.denied` | resource services (`TransactionEnforcer`), the agent tool runtime |
| `token.rejected` | resource services, when the token fails verification |
| `token.issued`, `issuance.denied` | the TTS |
| `token.replaced`, `replacement.denied` | the TTS |

Events carry the `txn`, subject, scope, policy id, reason code, requesting and calling workloads,
agent chain summary, an OpenTelemetry trace id when one is active, and a SHA-256 **digest** of the
token, never the token itself. Bound *values* are never recorded, only the names of the checked
fields. Built-in sinks: `LoggingSink` (JSON on the `pytrat.audit` logger), `JsonLinesSink`
(background-thread file writer), `MemorySink` (tests) and `NullSink`. Implement `emit(event)` to
send events anywhere else.

The TTS additionally persists every issuance and replacement in a hash-chained, append-only SQLite
log keyed by `txn`, from which call chains are reconstructed (P9).

## The payment flow

The [demo](getting-started.md#the-30-second-demo) end to end. Each internal hop carries two
independent credentials: the unchanged Txn-Token and a fresh workload JWT.

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant GW as api-gateway (edge)
    participant TTS as Transaction Token Service
    participant PAY as payment-service
    participant LED as ledger-service

    User->>GW: POST /transfers {account-A → account-B, 10000 USD}<br/>Authorization: Bearer <access token>
    GW->>GW: validate the transfer body (strict)
    GW->>TTS: POST /token (RFC 8693)<br/>subject_token = access token<br/>request_details = transfer<br/>client_assertion (RFC 7523)
    TTS->>TTS: authenticate api-gateway, validate access token,<br/>issuance policy: tctx = 4 allowlisted fields
    TTS-->>GW: Txn-Token {txn, sub=user:123, scope=payments.transfer, tctx}
    GW->>GW: verify Txn-Token locally (trusted JWKS)
    GW->>PAY: POST /internal/payments<br/>Txn-Token + Workload-Identity (api-gateway)
    PAY->>PAY: verify token, caller ∈ {api-gateway},<br/>bind body ↔ tctx
    alt honest payment-service
        PAY->>LED: POST /internal/ledger/entries (unchanged token)<br/>Workload-Identity (payment-service)
        LED->>LED: verify, caller ∈ {payment-service},<br/>body == tctx ✔
        LED-->>PAY: 201 recorded
        PAY-->>GW: 201
        GW-->>User: 201 (txn id)
    else compromised payment-service rewrites amount_minor to 900000
        PAY->>LED: POST /internal/ledger/entries {amount_minor: 900000}<br/>(same token; cannot re-sign it)
        LED->>LED: amount_minor ≠ tctx.amount_minor ✘<br/>audit: authorization.denied
        LED-->>PAY: 403 TRANSACTION_CONTEXT_MISMATCH
        PAY-->>GW: 403
        GW-->>User: 403
    end
```
