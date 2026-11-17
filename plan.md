# PyTraT implementation plan

Status: ready to implement. Written 2026-11-17 against
`draft-ietf-oauth-transaction-tokens-11` (published 2026-07-30) and
`draft-araut-oauth-transaction-tokens-for-agents-03` (published 2026-10-31).

Coding rules and security invariants live in `CLAUDE.md`. This file covers *what* to build, *in what
order*, and *why* each design choice was made.

---

## 1. Outcome

**v0.1 ships one complete, reproducible security story** (the "$100 → $9,000" demo):

1. A gateway authenticates a user and obtains a signed Transaction Token from a TTS.
2. A downstream service verifies it and binds it to the request body.
3. A tampered amount is rejected with `TRANSACTION_CONTEXT_MISMATCH` and a structured audit event.
4. The untampered request succeeds.
5. All of it runs with `docker compose up` or a single `uv run` command, no Kubernetes.

Everything before v0.1 exists to make that story true and tested. The agent profile, Django, CLI
polish and hardening follow.

### Quality bar

- Clean seams: a reader can understand `pytrat.core` without knowing any framework.
- Every normative rule is traceable: spec section → code comment → conformance test.
- Fail closed everywhere; no configuration can silently weaken enforcement.
- Sync and async without duplicated logic.
- Measured, not assumed, performance.

---

## 2. What the specifications actually require

Findings from reading both drafts. These override the original proposal where they differ.

### 2.1 Base draft (-11)

| Topic | Rule | Section |
|---|---|---|
| Header | `typ` MUST be `txntoken+jwt`; `kid` SHOULD be supported; **no `alg` rule** | 9.1 |
| Required claims | `aud`, `txn`, `sub`, `scope`, `req_wl`, `exp`, `iat` | 9.2 |
| Recommended | `tctx`, `rctx` (JSON objects, sub-fields undefined, TTS-authoritative) | 9.2.2, 9.2.3 |
| Optional | `iss` | 9.2 |
| Not defined | `jti` (use `txn`) | — |
| Unknown claims | recipients MUST ignore | 9.2 |
| `req_wl` | a **single string** | 9.2 |
| `scope` | space-delimited, case-sensitive; TTS-defined; need not equal requested | 9.2.1, 11.1 |
| Request | form-urlencoded; `grant_type`, `audience`, `scope`, `requested_token_type`, `subject_token`, `subject_token_type` REQUIRED; `request_context`, `request_details` RECOMMENDED JSON objects (URL-encoded, not base64) | 11.1 |
| Subject token types | any RFC 8693 type **except refresh_token**; `…:token-type:self_signed`; `…:token-type:unsigned_json`; custom URNs | 11.2 |
| Response | `token_type="N_A"`, `access_token=<JWT>`, `issued_token_type=…:txn_token`; MUST NOT include `refresh_token`; errors per RFC 6749 §5.2 | 11.4 |
| Authentication | TTS and workload MUST mutually authenticate; asymmetric / RFC 7523 / mTLS / WIMSE recommended | 11.5 |
| Propagation | `Txn-Token` header, exactly one token; `Authorization` MUST NOT be used; forward unmodified | 12.1, 12.2 |
| Receiver MUST | validate JWS signature, `aud` is own Trust Domain, not expired | 12.2 |
| Replacement | present Txn-Token as `subject_token`; MUST NOT change `txn`/`sub`/`aud`, MUST NOT expand, MUST NOT replace an expired token; lifetime MAY be extended, SHOULD limit replacement count if so | 13.15 |
| Scope | requested ≤ subject's scope; unknown subject scope → reject | 13.6, 13.14 |
| Lifetime | "order of minutes or less"; no number | 6, 13.1 |
| Issuance | MUST NOT issue if presented credential is expired; Txn-Token MUST NOT embed the access token | 6, 13.4 |
| Logging | full tokens MUST NOT be logged; hash or unsigned payload MAY be | 15.2 |
| Discovery | **none defined** (no metadata, no JWKS location) | — |

### 2.2 Agent draft (-03) — individual, informational, not WG-adopted

```
agentic_ctx (OPTIONAL)
├── originator        REQUIRED  { id: str REQUIRED, session_id: str OPTIONAL }   immutable
├── proximate_agent   REQUIRED  { id: str REQUIRED, session_id: str OPTIONAL }   updated on agent replacement
├── chain_metadata    REQUIRED  { hop_count: int REQUIRED, min_assurance_level: str OPTIONAL }
└── attr_store_ref    OPTIONAL  URI, informational only
```

- `hop_count` is **1 at initial issuance**, +1 per replacement requested by an agent (3.5.1).
- `min_assurance_level` = min(existing, new agent's level), recomputed on every replacement.
  Deployments MUST define the ordered set (3.5.1, 4.2).
- `originator`, `act`, `txn`, `sub`, `aud` copied unchanged (4.2.1). `act` MUST be absent for
  client-credentials (autonomous) flows (3.2.2).
- Non-agent requester: base replacement rules, `agentic_ctx` carried forward **unmodified** (3.3.2).
- `req_wl`: replacement MUST append the workload identifier, comma-separated (3.3.1).
- `session_id` MUST NOT be an authorization criterion; unknown `agentic_ctx` fields MUST be ignored (3.5.4).
- Agent Attribute Store: logical role only, no protocol; posture MUST NOT be self-asserted (3.6.2).
- No new token-exchange parameters; agent identified via `act.sub` → AAS lookup → `client_id`.

### 2.3 Gaps and the PyTraT profile decisions that fill them

Each is implemented behind a `# PyTraT profile:` comment and listed in `docs/compatibility.md`.

| # | Gap | Decision |
|---|---|---|
| P1 | No `alg` rule | Explicit allowlist, default `ES256`, `EdDSA`, `PS256`. `RS256` opt-in for interop. `none`/`HS*` hard-rejected, not configurable. |
| P2 | No key distribution | Trusted config supplies a JWKS (file, inline, or HTTPS URL pinned in config). Reference TTS serves `/.well-known/jwks.json`. `kid` required by default (`require_kid=True`). |
| P3 | No lifetime number | Verifier enforces `exp - iat ≤ max_lifetime` (default 300 s) and clock leeway (default 5 s, max 60 s). TTS default lifetime 60 s. |
| P4 | Replacement `subject_token_type` undefined | Use `urn:ietf:params:oauth:token-type:txn_token`. |
| P5 | `req_wl` is one string in base, comma-appended in agent draft (which cites a base rule that -11 does not contain) | Model stores the raw string. `requesting_workloads -> tuple[str, ...]` splits on `,` **only** under the agent profile. Workload identifiers containing `,` are rejected at TTS registration. |
| P6 | Agent draft: "min of existing and new" (3.3.1) vs "must not exceed incoming" (5.9); absent-value case unspecified | `new = min(existing, agent_level)`; if existing is absent on an agent-profile token, treat as the configured `default_assurance` (lowest by default). Satisfies both readings. |
| P7 | `iss` optional | Verifier takes `expected_issuer: str | None`; when set, `iss` is required and must match. |
| P8 | Replay "may not be feasible" | Tokens are legitimately reused within a transaction. Replay protection is opt-in per route: `single_use=True` records `(txn, operation)` in a `ReplayStore` until `exp`. |
| P9 | Call-chain maintenance mechanism out of scope | TTS persists every issuance/replacement event keyed by `txn`; the chain is reconstructed from the audit store, not the token. |

**Verification debt:** agent-draft sections 4.2.3, 5.x and 6–7 were read only in summary. M0 vendors
both drafts into `docs/spec/`; before starting M7, re-read those sections verbatim and reconcile
§2.2/P6 and the hop-limit and egress-stripping rules.

---

## 3. Architecture

### 3.1 Packages and dependency rules

```
                       ┌──────────────┐
                       │  pytrat-core │  claims · verify · scopes · binding · audit · errors
                       └──────┬───────┘
          ┌───────────┬───────┴────────┬────────────┐
   pytrat-policy  pytrat-client   pytrat-agents     │
          │           │                │            │
          ├───────────┤                └─────┐      │
   pytrat-fastapi  pytrat-django         pytrat-server (also uses policy)
                                             │
                                        pytrat-cli (uses all)
```

- One-way only, enforced by `import-linter` contracts in CI.
- `core` never imports a web framework, an HTTP client, or `agents`.
- `agentic_ctx` *parsing* lives in `core` (it is just claims; a verifier must be able to read it).
  Agent *rules* (attenuation, registry, runtime) live in `agents`.
- Audit event types and the `AuditSink` protocol live in `core` because every package emits them.
- `AssuranceOrdering` lives in `core` (`pytrat.core.assurance`), not `agents`: resource-side policy
  (`pytrat.policy`) must evaluate `minimum_assurance` without depending on the agent package.
  `pytrat.agents` re-exports it.

### 3.2 Design principles

| Principle | Concretely |
|---|---|
| Sans-IO | Exchange = `build_request(...) -> ExchangeRequest` + `parse_response(status, body) -> TokenResponse`, both pure. Sync/async clients are ~20-line shells around `httpx`. Verification is pure CPU given a key. |
| Ports and adapters | Small `Protocol`s at the consumer; in-memory + one real adapter each. |
| Immutable values | Frozen dataclasses/models; verification returns a `VerifiedToken` that cannot be constructed any other way (private constructor token). |
| Parse, don't validate | Raw → typed exactly once at the boundary. Downstream code never sees a `dict` of claims. |
| Explicit configuration | One frozen settings object per component, validated at startup. No env-var reads scattered in code. |
| Startup compilation | Keys parsed, policies compiled, binding paths resolved before the first request. Invalid config = process refuses to start. |
| Injected clock | `Clock` protocol; `SystemClock` and `FrozenClock`. |

### 3.3 Runtime dependencies (keep this table current)

| Package | Depends on | Why |
|---|---|---|
| core | `pyjwt[crypto]`, `pydantic>=2` | Audited JOSE; strict boundary parsing |
| policy | core, `pyyaml` | `yaml.safe_load` only |
| client | core, `httpx` | Sync + async with one API, mockable transport |
| fastapi | core, policy, client, `fastapi` | — |
| server | core, policy, agents, `fastapi`, `uvicorn`, `aiosqlite` | Reference TTS |
| agents | core | — |
| cli | all, `typer` | — |
| django | core, policy, client, `django>=5` | — |

Dev: `ruff`, `mypy`, `pytest`, `pytest-asyncio`, `pytest-cov`, `hypothesis`, `import-linter`,
`pre-commit`, `pytest-benchmark`, `mkdocs-material`.

PyJWT is wrapped entirely inside `pytrat.core.crypto`; nothing else imports `jwt`. Swapping the JOSE
library is a one-file change.

### 3.4 Repository layout

```
pytrat/
├── pyproject.toml              # uv workspace root: tool config only, no code
├── uv.lock
├── CLAUDE.md  plan.md  README.md  CHANGELOG.md  SECURITY.md  LICENSE (Apache-2.0)
├── .pre-commit-config.yaml  .github/workflows/ci.yml  .importlinter
├── packages/
│   ├── pytrat-core/
│   │   ├── pyproject.toml
│   │   ├── src/pytrat/core/
│   │   │   ├── __init__.py     # public API + __all__
│   │   │   ├── constants.py    # URNs, header names, typ
│   │   │   ├── errors.py       # PyTraTError tree, ReasonCode
│   │   │   ├── clock.py
│   │   │   ├── secret.py       # SecretStr-like Token wrapper (masked repr, digest())
│   │   │   ├── claims.py       # TransactionClaims, AgenticContext, …
│   │   │   ├── scopes.py       # Scope value type
│   │   │   ├── keys.py         # KeyProvider protocol, StaticKeySet, JWKS parsing
│   │   │   ├── crypto.py       # the only module importing `jwt`
│   │   │   ├── validation.py   # TokenVerifier, VerifierSettings, VerifiedToken
│   │   │   ├── binding.py      # tctx ↔ request binding
│   │   │   ├── replay.py       # ReplayStore protocol + InMemoryReplayStore
│   │   │   ├── audit.py        # AuditEvent, AuditSink, JsonLinesSink, NullSink
│   │   │   ├── testing.py      # TokenFactory, FrozenClock, key fixtures (test-only)
│   │   │   └── py.typed
│   │   └── tests/
│   ├── pytrat-policy/   src/pytrat/policy/{model,loader,compiler,evaluator}.py
│   ├── pytrat-client/   src/pytrat/client/{exchange,credentials,http,context,jwks}.py
│   ├── pytrat-fastapi/  src/pytrat/fastapi/{dependencies,middleware,enforcement,responses,settings}.py
│   ├── pytrat-server/   src/pytrat/server/{app,token_endpoint,workloads,subjects,issuance,replacement,signing,audit_store,settings}.py
│   ├── pytrat-agents/   src/pytrat/agents/{assurance,registry,replacement,runtime,policy}.py
│   ├── pytrat-cli/      src/pytrat/cli/
│   └── pytrat-django/   src/pytrat/django/
├── tests/
│   ├── integration/    # real ASGI apps wired together in-process
│   ├── conformance/    # one module per spec section, vectors in tests/conformance/vectors/
│   └── security/       # attack scenarios
├── examples/payment-transfer/  (gateway, payment, ledger, tts, docker-compose.yml, demo.py)
├── examples/agent-delegation/
├── benchmarks/
└── docs/  (spec/, compatibility.md, threat-model.md, guides/)
```

Namespace packaging: no `__init__.py` at `src/pytrat/`; hatchling with
`[tool.hatch.build.targets.wheel] packages = ["src/pytrat"]` in each package.

---

## 4. Detailed design

### 4.1 `pytrat.core`

**Errors (`errors.py`)**

```python
class ReasonCode(StrEnum):
    TOKEN_MISSING, TOKEN_MALFORMED, TOKEN_TYPE_INVALID, ALGORITHM_NOT_ALLOWED,
    KEY_UNKNOWN, SIGNATURE_INVALID, CLAIM_MISSING, CLAIM_INVALID,
    TOKEN_EXPIRED, TOKEN_NOT_YET_VALID, LIFETIME_EXCEEDED,
    TRUST_DOMAIN_MISMATCH, ISSUER_MISMATCH,
    SCOPE_INSUFFICIENT, TRANSACTION_CONTEXT_MISSING, TRANSACTION_CONTEXT_MISMATCH,
    CALLER_NOT_ALLOWED, WORKLOAD_UNAUTHENTICATED, REPLAY_DETECTED,
    POLICY_NOT_FOUND, POLICY_INVALID, DEPENDENCY_UNAVAILABLE,
    AGENT_UNVERIFIED, AGENT_HOP_LIMIT_EXCEEDED, AGENT_ASSURANCE_INSUFFICIENT,
    REPLACEMENT_WIDENS_AUTHORIZATION, DESTINATION_NOT_TRUSTED, EXCHANGE_FAILED

PyTraTError(reason: ReasonCode, detail: str)      # detail is safe to log
├── TokenError          → 401 at the HTTP edge
├── AuthorizationError  → 403
├── ConfigurationError  → raised at startup only
└── DependencyError     → 503 (and deny)
```

**Claims (`claims.py`)** — frozen Pydantic models, `strict=True`, `extra="ignore"` (§9.2).

- `TransactionClaims`: `aud: str`, `txn: str`, `sub: str`, `scope: Scope`, `req_wl: str`,
  `iat: int`, `exp: int`, `iss: str | None`, `tctx: FrozenJson | None`, `rctx: FrozenJson | None`,
  `act: FrozenJson | None`, `agentic_ctx: AgenticContext | None`.
- `aud` must be a single string (a list is `CLAIM_INVALID`: one token, one Trust Domain).
- `iat`/`exp` must be integers; reject bools, floats, numeric strings.
- Non-empty-string checks on `aud`, `txn`, `sub`, `req_wl`.
- `tctx`/`rctx` deep-frozen into `MappingProxyType` / tuples so callers cannot mutate.
- Convenience properties: `.id` (→ `txn`), `.trust_domain` (→ `aud`), `.expires_at`.
- Duplicate JSON keys in the payload are rejected at decode (`object_pairs_hook`) — ambiguity is an
  attack surface.

**Scopes (`scopes.py`)** — `Scope` wraps `frozenset[str]`; `parse("a b")`, `issubset`, `__contains__`,
canonical `str()` (sorted). Tokens validated against RFC 6749 `scope-token` grammar.

**Keys (`keys.py`)**

```python
class KeyProvider(Protocol):
    def get(self, kid: str | None) -> VerificationKey | None: ...   # in-memory, never does I/O

StaticKeySet.from_jwks(mapping | path)   # parses once; rejects private keys, `oct` keys, duplicate kids
```

Each `VerificationKey` is bound to the algorithms valid for its key type, so an EC key can never
verify an RS/HS token (key-confusion defence in depth on top of the allowlist).
Remote JWKS refresh is I/O and therefore lives in `pytrat.client.jwks` (§4.3), which produces a new
immutable `StaticKeySet` and swaps it atomically.

**Verification (`validation.py`)** — the heart of the project.

```python
@dataclass(frozen=True, slots=True)
class VerifierSettings:
    trust_domain: str
    algorithms: frozenset[str] = frozenset({"ES256", "EdDSA", "PS256"})
    expected_issuer: str | None = None
    max_lifetime: timedelta = timedelta(minutes=5)
    leeway: timedelta = timedelta(seconds=5)
    require_kid: bool = True
    max_token_bytes: int = 16_384

class TokenVerifier:
    def __init__(self, settings, keys: KeyProvider, clock: Clock = SystemClock()): ...
    def verify(self, raw_token: str) -> VerifiedToken: ...
```

Order of checks (each maps to one `ReasonCode`; order is fixed and tested):

1. Size and shape: ≤ `max_token_bytes`, exactly three base64url segments, non-empty signature.
2. Header peek: `typ == "txntoken+jwt"` (case-insensitive per RFC 7515 media-type rules), `alg` in
   allowlist, `kid` present; reject `crit`, `jwk`, `jku`, `x5u`, `x5c`, `b64`.
3. Key lookup by `kid` in trusted set; algorithm must be compatible with the key.
4. Signature verification (PyJWT, with PyJWT's own claim checks disabled so we own them).
5. Payload parse into `TransactionClaims`.
6. `aud == trust_domain`; `iss` if configured.
7. Time: `iat ≤ now + leeway`; `now < exp + leeway`; `exp > iat`; `exp - iat ≤ max_lifetime`.

`VerifiedToken` exposes `.claims`, `.digest` (SHA-256 hex, safe to log) and `.forwardable` (the raw
token inside the secret wrapper, for unchanged propagation only).

Unknown-`kid` handling: `verify` raises `KEY_UNKNOWN`; the integration layer may trigger one
rate-limited JWKS refresh and retry once. The verifier itself never does I/O.

**Context binding (`binding.py`)**

```python
binding = ContextBinding.compile(
    ["source_account", "destination_account", "amount_minor", "currency"]   # same name both sides
    # or {"amount": "amount_minor", "to.account": "destination_account"}   # request path → tctx path
)
binding.check(tctx, request_data)   # raises AuthorizationError(TRANSACTION_CONTEXT_MISSING | _MISMATCH)
```

- Dotted paths for nesting; compiled once into accessor tuples.
- Canonical comparison: exact type equality, then value. `bool` is not `int`. Floats rejected in
  bound positions (`CLAIM_INVALID`). Strings compared after NFC normalisation; no case folding, no
  trimming. Lists compared element-wise in order; mappings key-wise recursively.
- Missing on either side → deny.
- The mismatch error names the *field path* only, never either value.
- Explicit transforms for legitimate derived values: `Derived(request_path, tctx_path, fn, name=...)`;
  `fn` is pure, the transform name is recorded in the audit event. No implicit coercion ever.

**Audit (`audit.py`)**

```python
@dataclass(frozen=True, slots=True)
class AuditEvent:
    event_type: str            # authorization.granted | authorization.denied | token.issued | token.replaced | token.rejected
    timestamp: datetime        # UTC
    service: str
    transaction_id: str | None
    subject: str | None
    scope: str | None
    policy_id: str | None
    reason_code: ReasonCode | None
    requesting_workload: str | None
    caller_workload: str | None
    token_digest: str | None
    agent_context: AgentAuditContext | None
    trace_id: str | None       # from the active OpenTelemetry span if the API package is importable
    detail: Mapping[str, str]  # field paths, transform names — never values

class AuditSink(Protocol):
    def emit(self, event: AuditEvent) -> None: ...   # must not block and must not raise
```

Sinks: `NullSink`, `LoggingSink`, `JsonLinesSink` (bounded queue + background writer thread; on
overflow increments a drop counter and logs once — an audit outage must never become a request
outage, but drops must be visible). Schema is versioned (`schema_version: 1`) and documented.

**Testing helpers (`testing.py`)** — `generate_keypair(alg)`, `TokenFactory(key, defaults).mint(**overrides)`
(including deliberately malformed variants: `alg=none`, wrong `typ`, stripped signature),
`FrozenClock`. Imports from production modules are blocked by an import-linter contract.

### 4.2 `pytrat.policy`

YAML → strict Pydantic models (`extra="forbid"`, so typos fail loudly) → `CompiledPolicy`.

```python
policy_set = load_policy("policy.yaml")          # raises ConfigurationError with file:line context
decision = policy_set.for_route("POST", "/internal/transfer").evaluate(
    AuthorizationRequest(token=verified, caller=workload_identity, request_data=body)
)   # -> Decision(allowed, reason_code, policy_id)
```

- Schema follows the proposal's section 12 (`version`, `trust_domain`, `resources[...]` with
  `allowed_scopes`, `allowed_callers`, `bind_context`, `agents{...}`, plus `single_use`).
- Compile-time checks: unknown keys, duplicate `(method, path)`, empty `allowed_scopes`,
  `require_workload_identity: false` combined with `allowed_callers`, agent keys referencing
  assurance levels not in the configured ordering, `trust_domain` mismatch with verifier settings.
- Evaluation order: scope → caller → binding → agent constraints → replay. First failure wins;
  deterministic so audit reasons are stable.
- `default: deny`: a route with `require_transaction` middleware and no matching resource is denied
  (`POLICY_NOT_FOUND`).
- `PolicyEvaluator` is a `Protocol`, so an OPA/AuthZEN adapter can be added later without touching
  callers. Not built now.

### 4.3 `pytrat.client`

**Exchange (`exchange.py`)** — pure:

```python
build_issue_request(audience, scope, subject_token, subject_token_type,
                    request_context=None, request_details=None) -> ExchangeRequest
build_replacement_request(current: VerifiedToken, scope: Scope | None = None) -> ExchangeRequest
parse_exchange_response(status: int, headers, body: bytes) -> SecretToken
```

`parse_exchange_response` requires `token_type == "N_A"` (case-insensitive),
`issued_token_type == …:txn_token`, a non-empty `access_token`, and **rejects** responses carrying
`refresh_token`. RFC 6749 §5.2 errors map to `ExchangeError(reason=EXCHANGE_FAILED, oauth_error=...)`.
Refresh-token subject types are refused client-side before any request is sent.

**Shells:** `TransactionTokenClient` and `AsyncTransactionTokenClient` take an injected
`httpx.Client`/`AsyncClient`, a `WorkloadCredential`, the TTS URL (HTTPS required unless
`allow_insecure_localhost=True`), and a `TokenVerifier`. **Every token received from the TTS is
verified locally before it is returned** — the client does not trust the transport alone.

**Credentials (`credentials.py`)**

```python
class WorkloadCredential(Protocol):
    def apply(self, request: ExchangeRequest) -> ExchangeRequest: ...
```

Implementations: `PrivateKeyJwtCredential` (RFC 7523 client assertion, short-lived, `jti`, key loaded
from a file path, never from an inline config string), `MtlsCredential` (configures the httpx
transport), `SpiffeJwtSvidCredential` (reads a JWT-SVID from a file the SPIFFE helper rotates).
All have masked `repr`.

**Context (`context.py`)** — `ContextVar[VerifiedToken | None]`; `bind_transaction(token)` context
manager; `current_transaction()` raises if unset. Copy semantics work with asyncio tasks and
`anyio.to_thread`.

**Propagating HTTP client (`http.py`)** — `TransactionClient` / `AsyncTransactionClient` wrapping httpx:

- `trusted_destinations`: exact `scheme://host[:port]` allowlist; anything else raises
  `DESTINATION_NOT_TRUSTED` *before* a connection is made.
- Adds `Txn-Token` from the bound context; strips any caller-supplied `Txn-Token`/`Authorization`
  confusion (never copies the token to `Authorization`).
- `follow_redirects=False`, not overridable.
- Workload auth to the destination is a separate, pluggable `httpx.Auth`.
- Optional `replace_before_call` hook (used by the agent runtime) asks the TTS for a replacement.

**JWKS (`jwks.py`)** — `JwksRefresher` (sync + async shells over a pure `parse_jwks`): HTTPS only,
size cap, TTL refresh, single-flight, min interval between forced refreshes (unknown-`kid` storms
cannot be turned into a DoS of the TTS), keeps last good set on failure up to `max_stale`, then
fails closed.

### 4.4 `pytrat.fastapi`

```python
pytrat = PyTraT(settings, keys=..., policy=..., audit=..., workload_authenticator=...)
app = FastAPI(lifespan=pytrat.lifespan)          # compiles policy, loads keys, starts JWKS refresh

@app.post("/internal/transfer")
async def transfer(
    body: Transfer,
    txn: Annotated[Transaction, Depends(pytrat.require_transaction(
        scope="payments.transfer",
        bind_fields=["source_account", "destination_account", "amount_minor", "currency"],
    ))],
): ...
```

- `require_transaction(...)` returns a dependency that: reads exactly one `Txn-Token` header
  (zero → 401 `TOKEN_MISSING`, more than one → 400 `TOKEN_MALFORMED`), verifies, authenticates the
  caller via the `WorkloadAuthenticator` port, evaluates route policy, binds the parsed body, emits
  one audit event, binds the context var for downstream `TransactionClient` use, returns `Transaction`.
- Body binding uses the **validated Pydantic model** FastAPI already parsed (the dependency declares
  the same body parameter through a small generated signature), never re-parsed raw JSON, so what is
  compared is exactly what the handler receives.
- Inline arguments and YAML policy are two front-ends to the same `CompiledPolicy`; if both exist for
  a route they must agree or startup fails.
- `TransactionMiddleware` (optional, pure ASGI): enforces "every route under prefix X needs a
  transaction" so a forgotten dependency fails closed; handlers opt out explicitly with
  `@pytrat.exempt`. At startup, `pytrat.assert_all_routes_covered(app)` lists unprotected routes.
- Error body (RFC 9457 problem+json): `{"type": "...", "title": "...", "status": 403, "reason_code":
  "...", "transaction_id": "..."}`. No claim values, no internal detail.
- `initiate_transaction(...)` helper for the trusted edge: exchanges the incoming access token and
  binds the result.
- `WorkloadAuthenticator` port with `MtlsHeaderAuthenticator` (proxy-terminated mTLS, trusted proxy
  CIDRs required) and `WorkloadJwtAuthenticator` implementations.

### 4.5 `pytrat.server` (reference TTS)

`POST /token` (form-encoded, RFC 8693), `GET /.well-known/jwks.json`, `GET /healthz`.

Pipeline, each stage a pure function over typed inputs with its own tests:

```
parse_form → authenticate_workload → classify (issue | replace) →
  issue:   validate_subject → authorize_issuance → build_claims → sign → audit
  replace: verify_txn_token → authorize_replacement → attenuate → sign → audit
```

- **Form parsing:** reject duplicate parameters, unknown `grant_type`, wrong `requested_token_type`,
  missing required params, non-object `request_context`/`request_details`, refresh-token subject
  types. Errors are RFC 6749 §5.2 JSON (`invalid_request`, `invalid_client`, `invalid_scope`,
  `invalid_target`, …) with `Cache-Control: no-store`.
- **Workload authentication (`workloads.py`):** `WorkloadAuthenticator` port; MVP implementation is
  RFC 7523 `private_key_jwt` against a registry of workload public keys, with assertion `jti` replay
  cache. mTLS via trusted-proxy headers as second adapter.
- **Subject validation (`subjects.py`):** `SubjectTokenValidator` protocol keyed by
  `subject_token_type`. Ships: JWT access token against a configured issuer JWKS (yields `sub`,
  `scope`, `exp`, optional `act`, `client_id`); `self_signed` (§11.2.1: checks `iss`, `aud`=TTS,
  `iat`, `exp`); `unsigned_json` (§11.2.2) **disabled by default** and restricted to explicitly
  listed workloads. Expired or scope-less subjects are rejected (§6, §13.14).
- **Issuance policy (`issuance.py`):** YAML: which workload may request which scopes for which
  audience, max lifetime, which `request_details` keys may be copied into `tctx` (allowlist +
  per-key JSON type) and which `request_context` keys into `rctx`. The TTS constructs `tctx`/`rctx`;
  unlisted keys are dropped and recorded in the audit event (key names only). Granted scope =
  requested ∩ policy ∩ subject scope; empty → `invalid_scope`. Never embeds the subject token (§13.4).
- **Replacement (`replacement.py`):** `plan_replacement(current, requester, requested_scope) ->
  ReplacementPlan` pure function enforcing §13.15: immutables copied, scope ⊆ current, input not
  expired, lifetime capped at original `exp` by default (`extend_lifetime=False`; if enabled, a
  per-`txn` replacement counter enforces a limit). Agent rules are delegated to
  `pytrat.agents.replacement` when the profile is enabled.
- **Signing (`signing.py`):** `Signer` protocol (`sign(header, payload) -> str`, `public_jwks()`).
  `FileKeySigner` for development (PEM path, refuses world-readable files), designed so KMS/HSM
  adapters slot in. Rotation: multiple keys with `active`/`retiring` state; JWKS publishes both;
  retiring keys stay published for `max_lifetime + leeway` after deactivation.
- **`txn` generation:** UUIDv7 (time-ordered, good index locality). Stdlib `uuid.uuid7()` on Python
  3.14+; on 3.12/3.13 use a ~15-line local implementation rather than a dependency.
- **Audit store (`audit_store.py`):** `aiosqlite`, append-only table indexed on `txn`; each row holds
  a hash chain (`prev_hash`, `row_hash`) for tamper evidence. `IssuanceLog` protocol so PostgreSQL
  can follow.
- **Operational:** per-workload token-bucket rate limit (in-memory, port for Redis), request size
  cap, structured logs, `/metrics` deferred to M9.

### 4.6 `pytrat.agents` (experimental; versioned `agent-profile-03`)

- `assurance`: re-export of `pytrat.core.assurance.AssuranceOrdering(("unverified", "low", "medium", "high"))` — configured ordered
  tuple; `min(a, b)`, `at_least(a, b)`; unknown level → `CLAIM_INVALID` (never treated as lowest
  silently when *checking a requirement*, always treated as lowest when *computing a chain minimum*).
- `registry.py`: `AgentAttributeStore` protocol (`get(agent_id) -> AgentRecord | None`);
  `AgentRecord(id, name, owner, assurance_level, version, provenance, attributes)`;
  `YamlAgentStore`, `SqliteAgentStore`. Lookup failure → `DEPENDENCY_UNAVAILABLE`, deny.
- `replacement.py`: pure `next_agentic_ctx(current, requester: AgentRecord | None, limits)`:
  non-agent → unchanged; agent → proximate updated, `hop_count + 1`, `min_assurance` recomputed
  (P6), `max_hops` enforced, `req_wl` appended (P5). Initial issuance: `hop_count = 1`,
  originator = proximate; agent resolved via `act.sub` → AAS → `client_id`.
- `policy.py`: resource-side checks: `maximum_hops`, `minimum_assurance`, `require_verified_agent`
  (proximate agent present in the AAS), allowed originators. `session_id` is never an input.
- `runtime.py`: `ToolRuntime` + `@protected_tool(scope=..., resource=..., require_verified_agent=...)`.
  The runtime owns the token context; the decorated function and anything derived from model output
  receive only validated arguments. Tool results pass through a redaction guard that refuses to
  return strings matching a compact-JWS shape. Documentation states plainly that an in-process
  decorator is not an isolation boundary; `examples/agent-delegation` runs the runtime as a separate
  process from the "model" to show the recommended deployment.
- Property tests (Hypothesis): for any sequence of replacements, scope is non-increasing, assurance
  non-increasing, `hop_count` strictly increasing by 1 per agent hop, immutables constant.

### 4.7 CLI and Django (after v0.1)

- `pytrat keys generate|rotate`, `pytrat policy check <file>`, `pytrat token inspect` (decodes
  header/payload, prints **no signature**, labels output UNVERIFIED unless `--jwks` verifies it),
  `pytrat tts serve`, `pytrat demo`.
- Django: `TransactionMiddleware`, `@require_transaction`, `request.transaction`; reuses core,
  policy and client unchanged. Sync views use the sync verifier directly (it is CPU-only).

---

## 5. Performance plan

Targets are hypotheses to measure, not promises.

| Path | Approach | Target (single core, laptop) |
|---|---|---|
| Local verify (ES256) | pre-parsed keys, no I/O, one JSON decode | p50 < 150 µs |
| Verify, repeated token | optional bounded LRU keyed by token digest, entry TTL = `exp`; off by default | p50 < 10 µs |
| Policy + binding | compiled accessors, no reflection per request | < 20 µs |
| Audit emit | enqueue only | < 5 µs |
| Exchange | pooled HTTP/1.1 keep-alive (HTTP/2 optional); TTS signing dominates | measure |

`benchmarks/` (pytest-benchmark + a small load script) compares the four configurations from the
proposal (unprotected / local verify / remote issuance / agent replacement) and reports local-crypto
and network cost separately. Results published with hardware and commit hash.

Rules: no caching of *decisions*, only of signature verification; the cache re-checks `exp` on every
hit; nothing on the request path takes a lock held across I/O.

---

## 6. Testing strategy

| Layer | Location | Content |
|---|---|---|
| Unit | `packages/*/tests` | Every public function; every `ReasonCode` reachable and asserted |
| Property | same | Scope algebra, binding canonicalisation, attenuation monotonicity, form/JWS parser robustness |
| Conformance | `tests/conformance/test_s09_token_format.py`, `…s11_exchange.py`, `…s12_propagation.py`, `…s13_replacement.py`, `…agents_s03.py`, … | One test per MUST/SHOULD, docstring cites the section; shared JSON vectors in `vectors/` reusable by other implementations |
| Integration | `tests/integration` | Gateway + service + TTS in-process via `httpx.ASGITransport`; key rotation mid-flight; TTS outage → fail closed |
| Security | `tests/security` | See below |
| Interop | `tests/interoperability` (M9) | Tokens from/to Tokenetes; skipped unless the external binary is available |

Security scenarios (named for the attack): `alg=none`; stripped signature; HS256 signed with the RSA/EC
public key; `jwk`/`jku` header injection; unknown `kid`; `kid` path/SQL-ish strings; wrong `typ`;
`aud` as list containing the right domain; expired / future `iat` / over-long lifetime; duplicate JSON
keys; oversized token; two `Txn-Token` headers; token in `Authorization`; tampered body field (the
demo); type-juggled body (`"10000"`, `10000.0`, `True`); missing bound field; scope widening on
replacement; replacing an expired token; changing `sub`/`txn`/`aud` via request parameters; assurance
laundering through a high-assurance agent; hop-limit bypass; non-agent replacement mutating
`agentic_ctx`; redirect to an untrusted host; outbound call to an unlisted host; refresh token as
subject; `refresh_token` in TTS response; unauthenticated workload; replayed client assertion;
registry unavailable; token appearing in any log record or exception string (a log-capturing fixture
scans every test's output for compact-JWS patterns and fails the test if one appears).

CI matrix: Python 3.12, 3.13, 3.14 on Linux; lint + mypy + import-linter + tests + coverage gate;
`uv lock --check`; `pip-audit`.

---

## 7. Milestones

Each milestone is independently mergeable and ends green. Sizes are relative (S/M/L).

### M0 — Scaffolding (S)
- `git init`; uv workspace; root `pyproject.toml` with ruff (rules: `E,F,W,I,B,UP,S,SIM,RUF,PT,TCH,ANN,D` Google convention, `S101` allowed in tests), mypy strict, pytest config.
- Eight package skeletons with `py.typed`; import-linter contracts; pre-commit; GitHub Actions CI.
- `LICENSE` (Apache-2.0), `README.md` stub, `SECURITY.md`, `CHANGELOG.md`.
- Vendor both drafts as text into `docs/spec/`; start `docs/compatibility.md` from §2.3.
- **Done when:** `uv sync --all-packages && uv run ruff check . && uv run mypy && uv run pytest` passes on an empty suite and CI is green.

### M1 — `pytrat-core` (L) — *proposal Phase 1*
Order: `constants` → `errors` → `clock`, `secret` → `scopes` → `claims` → `keys` → `crypto` →
`validation` → `binding` → `replay` → `audit` → `testing`. Tests land with each module.
- **Done when:** conformance suites for §9 and §12.2 pass; all token-validation tests from the
  proposal's section 17 pass; core coverage ≥ 95% branch; a verify benchmark exists.

### M2 — `pytrat-policy` (M)
Model → loader → compiler → evaluator.
- **Done when:** the proposal's sample YAML loads; every invalid-policy case fails at load with a
  precise message; evaluation order tests pass.

### M3 — `pytrat-client` (M)
`exchange` (pure) → `credentials` → shells → `context` → `http` → `jwks`.
- **Done when:** §11 request/response conformance passes against a mock transport; allowlist and
  redirect attack tests pass; sync and async shells share 100% of protocol logic (no duplicated
  branches — reviewed, plus identical test parametrisation over both).

### M4 — `pytrat-server` minimal TTS (L) — *enough of Phase 3 for the demo*
Form parsing → workload auth (private_key_jwt) → JWT subject validator → issuance policy → signing +
JWKS → audit store → base replacement.
- **Done when:** issuance tests from section 17 pass; replacement immutability/attenuation tests
  pass; response conforms to §11.4; client (M3) ↔ server round-trip integration test passes.

### M5 — `pytrat-fastapi` (M) — *proposal Phase 2*
Settings/lifespan → `require_transaction` → body binding → error responses → middleware + coverage
assertion → `initiate_transaction`.
- **Done when:** in-process three-service integration test passes: legitimate request succeeds,
  tampered amount → 403 `TRANSACTION_CONTEXT_MISMATCH` + audit event, wrong caller → 403, missing
  token → 401.

### M6 — Demo and v0.1.0 (M) — *proposal section 21*
- `examples/payment-transfer`: gateway, payment (with a `--compromised` flag that rewrites the
  amount), ledger, TTS; `docker-compose.yml`; `demo.py` that narrates both runs and prints the audit
  event.
- README quickstart, threat model, compatibility page, first benchmark numbers.
- **Done when:** a fresh clone reproduces the story with one command in under two minutes;
  the demo itself runs as an integration test in CI.

### M7 — `pytrat-agents` (L) — *proposal Phase 4*
First: re-read agent draft §4.2.3 and §5–7 verbatim and reconcile (§2.3 note).
Then `assurance` → `registry` → `replacement` → server wiring → `policy` → `runtime` → example.
- **Done when:** agent replacement tests from section 17 pass; property tests prove monotonic
  attenuation; `examples/agent-delegation` shows a low-assurance external agent failing to gain
  authority via a high-assurance internal agent.

### M8 — Developer experience (M) — *proposal Phase 5*
CLI; Django package + example; mkdocs site; full server features deferred from M4 (key rotation
lifecycle, rate limiting, mTLS adapter, `self_signed` subject type).

### M9 — Hardening (L) — *proposal Phase 6*
Fuzzing (Atheris on token/form/JWKS parsers); failure injection (TTS, JWKS, AAS, audit sink down);
multi-instance replay store (Redis adapter) and consistency tests; Tokenetes interop; OpenTelemetry
exporter; external security review; published benchmark report.

---

## 8. Risks and open decisions

| Item | Position | Needs user input? |
|---|---|---|
| Both specs are drafts and will change | Version-pin in `pytrat.core.constants.SUPPORTED_DRAFTS`; profile decisions isolated and documented; conformance tests named by section so a new revision produces a reviewable diff | No |
| Agent draft is an individual submission | Ship as `experimental`, separate package, separate version line, off by default in server | No |
| `req_wl` comma-append conflicts with base `-11` text (P5) | Implement as profile; consider raising with the draft authors | Optional |
| PyJWT vs joserfc | PyJWT, isolated in one module | No |
| Pydantic in core | Accepted for strict boundary parsing; internal values stay dataclasses | No |
| PyPI names `pytrat-*` and license | Assumed available / Apache-2.0 — check before first publish | **Yes, before M6** |
| Body binding for non-JSON bodies (form, multipart, query/path params) | v0.1 binds the validated body model and path/query params by name; multipart out of scope | No |
| Replay semantics across instances | In-memory is per-process and documented as such; Redis in M9 | No |

## 9. Explicitly out of scope

Cross-trust-domain forwarding (spec points to identity chaining), acting as an OAuth authorization
server, service-mesh/Kubernetes integration, policy languages beyond the YAML schema (ports exist),
and any API that lets application or model code sign tokens.
