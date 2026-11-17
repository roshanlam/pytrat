# Running the TTS

`pytrat-server` is a reference **Transaction Token Service**: the token endpoint of
`draft-ietf-oauth-transaction-tokens-11` (RFC 8693 token exchange with RFC 7523 workload
authentication), replacement (§13.15), key rotation, per-workload rate limiting, a hash-chained
issuance log and the experimental agent profile. It is the only PyTraT package that holds signing
keys.

```bash
uv add pytrat-server          # or pytrat-cli, which depends on it
```

## Run it

```bash
pytrat tts serve --config tts.yaml --host 127.0.0.1 --port 8080
# or, without the CLI:
python -m pytrat.server --config tts.yaml --host 127.0.0.1 --port 8000
```

| Route | Purpose |
|---|---|
| `POST /token` | The Txn-Token request (§11), `application/x-www-form-urlencoded`. Replies carry `Cache-Control: no-store`. |
| `GET /.well-known/jwks.json` | The public signing keys, active and retiring (P2). Cacheable for 5 minutes. |
| `GET /healthz` | Liveness. |

OpenAPI and interactive docs are disabled. Errors are RFC 6749 §5.2 JSON (`error`,
`error_description`) and never include internal details; the PyTraT reason code is recorded in the
audit log.

To embed the TTS in your own process, build it from settings:
`create_app(build_components(load_settings("tts.yaml")))`, or `create_app_from_settings(path)`.
`build_components` also accepts a `clock` and an audit `sink` (default: `LoggingSink`).

!!! warning "Production checklist"
    * Terminate TLS in front of the TTS; workloads refuse plain-HTTP token endpoints (except
      loopback in development).
    * Rate limiting is per **authenticated** workload. Put the TTS behind an ingress rate limiter
      to bound unauthenticated floods.
    * Set `audit_db_path`; without it the issuance log is in memory and a warning is logged.
    * Private key files must be mode `0600`; the TTS refuses keys readable by group or others.
    * The client-assertion `jti` replay cache is per process. Run one instance, or pin each
      workload to an instance, until a shared replay store is configured.

## Configuration

The file is YAML, validated strictly at startup by the `TtsSettings` model: unknown keys, wrong
types (`"60"` is not an integer) and inconsistent values stop the process with a message naming the
failing location. YAML-only types such as dates are rejected. Relative paths resolve against the
directory of the configuration file.

An annotated example ships with the package (it is also validated by the documentation tests):

??? example "packages/pytrat-server/examples/tts.yaml"
    ```yaml
    --8<-- "packages/pytrat-server/examples/tts.yaml"
    ```

### Reference

Every key, its type and its default. "required" means the key has no default.

#### Top level

| Key | Type | Default | Meaning |
|---|---|---|---|
| `trust_domain` | string | required | The Trust Domain. Issued tokens carry it as `aud`; requests must ask for exactly this audience (§11.1). |
| `issuer` | string | required | Value of the `iss` claim. |
| `token_endpoint` | URL | required | Absolute `http(s)` URL of `POST /token` as workloads reach it. RFC 7523 assertions must name it in `aud`. |
| `token_lifetime_seconds` | integer 1–300 | `60` | Lifetime of issued tokens (§6, P3). |
| `leeway_seconds` | integer 0–60 | `5` | Clock-skew tolerance for assertions and input Txn-Tokens. Subject-token and replacement-input expiry are checked with no leeway. |
| `algorithms` | list of strings | `[ES256]` | Algorithms the TTS signs with and accepts for client assertions and self-signed subjects. `none` and `HS*` are rejected. |
| `signing_keys` | list | required | At least one; see [signing keys](#signing-keys). |
| `workloads` | list | `[]` | Registered workloads; see [workloads](#workloads). |
| `workload_auth` | object | see below | How workloads authenticate. |
| `subject_tokens` | object | see below | Accepted subject token types. |
| `issuance_policy` | object | see below | Who may obtain what. |
| `replacement` | object | see below | Replacement policy. |
| `agents` | object | see below | Experimental agent profile. |
| `audit_db_path` | path | unset | Hash-chained, append-only SQLite issuance log (P9). Unset: in memory only (development). |
| `rate_limit` | object | see below | Per-workload token bucket. |
| `max_request_bytes` | integer 1024–1048576 | `32768` | Largest accepted request body; larger bodies get HTTP 413. |

#### Signing keys

Exactly one key is `active` and signs; `retiring` keys stay in the published JWKS so tokens they
signed keep verifying. Remove a retiring key only after the maximum token lifetime plus leeway has
passed. Every `alg` must be listed in `algorithms`, and `kid`s must be unique.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `signing_keys[].kid` | string | required | Key identifier published in the JWKS and the token header. |
| `signing_keys[].alg` | string | required | Signing algorithm; must match the key type. |
| `signing_keys[].private_key_path` | path | required | PEM private key, mode `0600`. |
| `signing_keys[].state` | `active` or `retiring` | `active` | Lifecycle state. |

Generate keys with [`pytrat keys generate`](cli.md#pytrat-keys-generate) and publish an active and
a retiring key together with [`pytrat keys jwks`](cli.md#pytrat-keys-jwks).

#### Workloads

| Key | Type | Default | Meaning |
|---|---|---|---|
| `workloads[].id` | string | required | Workload identifier (unique; must not contain `,`, P5). |
| `workloads[].jwks_path` | path | unset | Public keys for RFC 7523 assertions. Exactly one of `jwks_path` and `jwks`. |
| `workloads[].jwks` | object | unset | The same JWKS inline. |
| `workloads[].allowed_audiences` | list of strings | unset | Optional restriction; every entry must equal `trust_domain`. |

Every `kid` must be unique across all workloads: an assertion's `kid` identifies its workload.

#### Workload authentication

Mutual authentication is required (§11.5); at least one method must be enabled.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `workload_auth.private_key_jwt` | boolean | `true` | RFC 7523 client assertions, single-use `jti`. |
| `workload_auth.max_assertion_lifetime_seconds` | integer 1–300 | `300` | Assertions with a later `exp` are refused (P15). |
| `workload_auth.trusted_proxy` | object | see below | Identity asserted by a TLS-terminating proxy. Unset: disabled. |
| `workload_auth.trusted_proxy.header` | string | required | Header carrying the workload id (for example a SPIFFE ID). |
| `workload_auth.trusted_proxy.trusted_cidrs` | list of CIDRs | required | The header is honoured only when the TCP peer is inside one of these; from any other peer it is rejected as an attack. |

#### Subject tokens

Refresh tokens are always refused (§13.3). A subject without a scope is rejected (§13.14).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `subject_tokens.jwt_access_token` | list | `[]` | Trusted issuers of JWT access tokens (`access_token` and `jwt` subject types). |
| `subject_tokens.jwt_access_token[].issuer` | string | required | Expected `iss`. |
| `subject_tokens.jwt_access_token[].jwks_path` | path | required | The issuer's public keys, pinned locally (never fetched from the token). |
| `subject_tokens.jwt_access_token[].audience` | string | required | Expected `aud` of the access token. |
| `subject_tokens.jwt_access_token[].algorithms` | list of strings | `[ES256]` | Accepted algorithms. |
| `subject_tokens.self_signed` | object | see below | Self-signed JWT subjects (§11.2.1). |
| `subject_tokens.self_signed.enabled` | boolean | `false` | Accept JWTs signed by the requesting workload's own registered keys, with `aud` = this TTS. They may not carry `act` (P28). |
| `subject_tokens.self_signed.max_age_seconds` | integer 1–3600 | `300` | Maximum age of a self-signed subject. |
| `subject_tokens.unsigned_json` | object | see below | Unsigned JSON subjects (§11.2.2). |
| `subject_tokens.unsigned_json.allowed_workloads` | list of strings | `[]` | Registered workloads allowed to send them. Empty: disabled. |

#### Issuance policy

A workload without a rule obtains nothing (§13.10). Granted scope is the requested scope ∩ the
rule's `scopes` ∩ the subject token's scope (§13.6); an empty result is `invalid_scope`.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `issuance_policy.workloads` | mapping of workload id to rule | `{}` | Must name only registered workloads. |
| `issuance_policy.workloads.<id>.scopes` | list of scope tokens | required | Scopes the workload may request (at least one). |
| `issuance_policy.workloads.<id>.audiences` | list of strings | `[]` | Audiences it may request; each must equal `trust_domain`. Empty: the Trust Domain only. |
| `issuance_policy.workloads.<id>.max_lifetime_seconds` | integer 1–300 | unset | Lifetime cap for this workload, below the global one. |
| `issuance_policy.workloads.<id>.tctx` | mapping of key to JSON type | `{}` | `request_details` members copied into `tctx`. |
| `issuance_policy.workloads.<id>.rctx` | mapping of key to JSON type | `{}` | `request_context` members copied into `rctx`. `authn` is reserved: the TTS derives it from the subject token. |
| `issuance_policy.workloads.<id>.may_replace` | boolean | `false` | May present a Txn-Token for replacement. |
| `issuance_policy.cap_lifetime_at_subject_exp` | boolean | `true` | Cap `exp` at the subject token's `exp` (P26). |

JSON types for `tctx`/`rctx` allowlists: `string`, `integer`, `boolean`, `object`, `array`,
`number`. Only `number` accepts floats; objects and arrays may not contain floats anywhere.
Unlisted members are dropped and their **names** audited; an allowlisted member with the wrong type
rejects the request (P24).

#### Replacement

| Key | Type | Default | Meaning |
|---|---|---|---|
| `replacement.extend_lifetime` | boolean | `false` | Allow a replacement to outlive its input token. |
| `replacement.max_replacements_per_txn` | integer 1–1000 | `10` | With `extend_lifetime`, how many lifetime-extending replacements one `txn` may have (`REPLACEMENT_LIMIT_EXCEEDED`). |

#### Agents (experimental)

See [Agents](agents.md).

| Key | Type | Default | Meaning |
|---|---|---|---|
| `agents.enabled` | boolean | `false` | Enable the agent profile. |
| `agents.max_hops` | integer 1–10000 | `5` | A replacement whose resulting `hop_count` exceeds this is refused (P17). |
| `agents.assurance_levels` | list of strings | `[unverified, low, medium, high]` | Ordering, lowest first; unique. |
| `agents.default_assurance` | string | unset | Level assumed when a chain recorded none; must be one of `assurance_levels`. |
| `agents.registry_path` | path | unset | The Agent Attribute Store (YAML). Required when `enabled`. |
| `agents.include_assurance` | boolean | `true` | Record `min_assurance_level` at issuance. |
| `agents.require_replacement` | boolean | `true` | An agent may not replace a token that has no `agentic_ctx` (P20). |
| `agents.attr_store_ref` | string | unset | Informational `attr_store_ref` placed in `agentic_ctx`. Internal: remove it with `pytrat.agents.strip_for_egress` before anything leaves the Trust Domain (P21). |

#### Rate limiting

| Key | Type | Default | Meaning |
|---|---|---|---|
| `rate_limit.requests_per_second` | number | `50.0` | Refill rate per authenticated workload. Over the limit: HTTP 429 `slow_down`. |
| `rate_limit.burst` | integer | `100` | Bucket size. |

## Cross-field rules

Checked at startup, in addition to the per-key constraints above:

* exactly one signing key is `active`, `kid`s are unique, and every key's `alg` is in `algorithms`;
* no configured algorithm (including subject-token issuers') is `none`, `HS*` or unsupported;
* workload ids are unique, and `issuance_policy.workloads` and
  `subject_tokens.unsigned_json.allowed_workloads` name only registered workloads;
* every allowed audience equals `trust_domain`;
* with `agents.enabled`, `agents.registry_path` is set.
