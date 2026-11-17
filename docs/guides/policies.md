# Policies

Route policies can be declared inline (`require_transaction(scope=..., ...)`) or in a YAML file
that security reviewers can read on its own. Both compile to the same immutable `CompiledPolicy`
with the same validation, so an inline declaration and a YAML resource with the same settings are
equal, and the FastAPI integration refuses to start if the two disagree for a route.

This page is about **resource-side** policy (`pytrat-policy`): what a service requires before it
acts. What the TTS is willing to *issue* is configured separately, in the
[TTS issuance policy](tts.md#issuance-policy).

## Example

```yaml title="policy.yaml"
--8<-- "docs/snippets/policy.yaml"
```

Loading it in a FastAPI service:

```python
--8<-- "docs/snippets/policy_app.py"
```

`load_policy` also accepts an already-parsed mapping; `load_policy_text` parses a YAML string.
Pass `expected_trust_domain` so that a policy written for another Trust Domain is refused.

## Schema reference (version 1)

Every mapping forbids unknown keys and every value is strictly typed (`"true"` is not a boolean,
`"3"` is not an integer), so a typo fails loudly instead of silently dropping a constraint.
Duplicate YAML keys are rejected. Errors read `<file>: <location>: <problem>` and never echo
configured values.

### Document

| Key | Type | Default | Meaning |
|---|---|---|---|
| `version` | integer | required | Schema version. Only `1` is supported. |
| `trust_domain` | string | required | The Trust Domain this policy is for. |
| `assurance_levels` | list of strings | unset | Agent assurance ordering, lowest first. Unset: `unverified < low < medium < high`. |
| `resources` | list | required | At least one resource. |

### Resource

| Key | Type | Default | Meaning |
|---|---|---|---|
| `resources[].name` | string | required | Policy id: recorded in decisions and audit events, used as the replay key, and selected with `policy_id=`. Letters, digits, `.`, `_`, `-`; at most 128 characters. |
| `resources[].path` | string | required | Route path, exact or with `{param}` segments. |
| `resources[].method` | string | required | HTTP method. |
| `resources[].require_transaction` | boolean | `true` | Require a Txn-Token. When `false`, only the caller is checked and no token-dependent key may be set. |
| `resources[].require_workload_identity` | boolean | `true` | Require an authenticated caller. |
| `resources[].allowed_scopes` | list of scope tokens | `[]` | The token's scope must contain at least one. Required (non-empty) when a transaction is required. |
| `resources[].allowed_callers` | list of strings | unset | Permitted calling workloads. Unset: any authenticated caller. Must not be empty; cannot be combined with `require_workload_identity: false`. |
| `resources[].bind_context` | list of paths, or mapping | `[]` | Request ↔ `tctx` binding: a list of dotted paths bound identically, or `{request path: tctx path}`. |
| `resources[].single_use` | boolean | `false` | Reject a second use of the same `txn` on this resource until the token expires (P8). Requires a replay store. |
| `resources[].agents` | object | see below | Agent-chain constraints. |

### Agents block

| Key | Type | Default | Meaning |
|---|---|---|---|
| `resources[].agents.enabled` | boolean | `false` | Apply agent constraints. Every other key requires `enabled: true`. |
| `resources[].agents.maximum_hops` | integer ≥ 1 | unset | Deny when `chain_metadata.hop_count` exceeds this (`AGENT_HOP_LIMIT_EXCEEDED`). Satisfied by a token without `agentic_ctx`. |
| `resources[].agents.minimum_assurance` | string | unset | Deny when the chain's `min_assurance_level` is below this, absent or unknown (`AGENT_ASSURANCE_INSUFFICIENT`). Must be a known level. |
| `resources[].agents.require_chain_replacement` | boolean | `false` | Recorded for the TTS and audit; not enforced by the resource. |
| `resources[].agents.require_agent_context` | boolean | `false` | Deny tokens without `agentic_ctx` (`AGENT_CONTEXT_MISSING`). |
| `resources[].agents.require_verified_agent` | boolean | `false` | Deny unless the originator and proximate agent are registered in the configured agent directory (`AGENT_UNVERIFIED`). Requires an agent directory. |
| `resources[].agents.allowed_originators` | list of strings | unset | The originating agent must be one of these (`AGENT_NOT_ALLOWED`). |

`minimum_assurance`, `allowed_originators`, `require_verified_agent` and `require_agent_context`
all deny a token that carries no `agentic_ctx` (P30): a constraint about the agent chain cannot be
met by omitting the chain.

## How a request is evaluated

**Route lookup is default-deny.** A `(method, path)` with no policy is refused with
`POLICY_NOT_FOUND`. Paths match exactly, or against `{param}` templates where a parameter matches
exactly one non-empty segment. An exact path takes precedence over a template, and two templates
that could match the same path are rejected at compile time, so lookup is never ambiguous.

**Checks run in a fixed order and the first failure wins**, so the audited reason for a given
request is stable:

1. a transaction is required and present (`TOKEN_MISSING`; token verification failures are
   reported before policy evaluation);
2. scope (`SCOPE_INSUFFICIENT`);
3. caller (`WORKLOAD_UNAUTHENTICATED`, `CALLER_NOT_ALLOWED`);
4. context binding (`TRANSACTION_CONTEXT_MISSING`, `TRANSACTION_CONTEXT_MISMATCH`);
5. agent constraints (`AGENT_CONTEXT_MISSING`, `AGENT_HOP_LIMIT_EXCEEDED`,
   `AGENT_ASSURANCE_INSUFFICIENT`, `AGENT_NOT_ALLOWED`, `AGENT_UNVERIFIED`);
6. replay (`REPLAY_DETECTED`).

Replay is last so that a request denied for any other reason never consumes the single use.

## Fail-closed compile-time rules

Policies are compiled once at startup. Settings that would be silently ignored are errors:

* `single_use: true` without a replay store, or `require_verified_agent: true` without an agent
  directory, fails with `DEPENDENCY_UNAVAILABLE`: a missing dependency never turns into an open
  route;
* agent constraints with `agents.enabled: false`;
* `allowed_scopes`, `bind_context`, `single_use` or `agents.enabled` with
  `require_transaction: false`;
* an empty `allowed_callers` list (omit it to allow any authenticated caller);
* a `tctx` path bound twice, or a malformed path;
* a `minimum_assurance` that is not in the assurance ordering.

## Framework support

| | FastAPI | Django |
|---|---|---|
| Select a resource | `require_transaction()` (by route) or `require_transaction(policy_id=...)` | `@require_transaction(policy_id=...)` |
| Replay store / agent directory | `load_policy(..., replay_store=..., agent_directory=...)` | `PYTRAT["REPLAY_STORE"]`, `PYTRAT["AGENT_DIRECTORY"]` |
| `require_transaction: false` resources | refused at startup (use `@pytrat.exempt` for unguarded routes) | supported: caller-only check |

## Replay stores

`InMemoryReplayStore` records `(txn, policy)` until the token expires. It is per process: with
several replicas, a token can be used once *per replica*. Multi-instance deployments need a shared
store; see [Replay protection across instances](../operations/redis-replay.md).

## Validating a policy

```bash
pytrat policy check policy.yaml --trust-domain payments.internal
```

On success it prints `OK: <n> route(s)` and one `METHOD path -> name` line per resource; on
failure it prints `invalid policy: <file>: <location>: <problem>` and exits with status 1.

!!! warning "`pytrat policy check` and dependencies"
    The command compiles the file "exactly as a service would", but without a replay store or an
    agent directory. A policy that uses `single_use: true` or `require_verified_agent: true` is
    therefore reported as invalid (`requires a replay store` / `requires an agent directory`) even
    though it loads in a service that provides them. The example above uses `single_use` and is
    validated by the documentation tests through `load_policy` instead.
