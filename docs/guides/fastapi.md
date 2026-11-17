# FastAPI

`pytrat-fastapi` turns Transaction Token enforcement into a FastAPI dependency. One `PyTraT`
object per service holds the verifier, the workload authenticator, the audit sink and (optionally)
a YAML policy; each route declares what it requires.

```bash
uv add pytrat-fastapi
```

## Wiring

```python
--8<-- "docs/snippets/first_route.py"
```

| `PyTraT(...)` argument | Purpose |
|---|---|
| `service` | This service's name, recorded in every audit event. |
| `verifier` | A `TokenVerifier` (or any function `str -> VerifiedToken` with the same contract). |
| `authenticator` | Authenticates the calling workload. Without one, every policy that requires workload identity (the default) denies. |
| `policy` | A `PolicySet` from `pytrat.policy.load_policy`; see [Policies](policies.md). |
| `audit` | An `AuditSink`. Defaults to `NullSink`: pass a real sink in production. |
| `protected_prefixes` | Paths that must be guarded by `require_transaction` or explicitly exempt. |
| `replay_store` | Required by inline `single_use=True` policies. |
| `agent_directory` | Required by inline agent policies with `require_verified_agent`. |
| `jwks_refresher` | An `AsyncJwksRefresher` whose `.keys` the verifier uses; refreshed at startup and on an unknown `kid`. |
| `debug` | Include the failed check's description (`detail`, never values) in error responses. |

Then:

* `app = FastAPI(lifespan=pytrat.lifespan)` compiles every route's policy at startup, checks that
  every route under a protected prefix is covered, and loads the JWKS. With your own lifespan,
  enter `pytrat.lifespan(app)` inside it:

    ```python
    --8<-- "docs/snippets/fastapi_extras.py:lifespan"
    ```

* `pytrat.install(app)` registers the RFC 9457 error handler and, when `protected_prefixes` is
  set, the fail-closed `TransactionMiddleware`.

## Declaring a route's policy

`pytrat.require_transaction(...)` returns a dependency. Use it as
`Annotated[Transaction, Depends(dependency)]`. It accepts three forms:

| Form | Example | Policy used |
|---|---|---|
| Inline | `require_transaction(scope="payments.transfer", bind_fields=[...])` | Compiled immediately. If a YAML resource also matches the route, the two must agree. |
| By name | `require_transaction(policy_id="account-read")` | The YAML resource with that `name`. |
| By route | `require_transaction()` | The YAML resource whose `(method, path)` equals the route template. |

Inline arguments:

| Argument | Meaning |
|---|---|
| `scope` / `scopes` | One allowed scope, or several; the token needs at least one. |
| `bind_fields` | Field paths, a `{request path: tctx path}` mapping, `Derived` rules, or a compiled `ContextBinding`. Names refer to the route's path, query and body fields. |
| `allowed_callers` | Permitted calling workloads. `None` allows any authenticated caller. |
| `require_workload_identity` | Require an authenticated caller (default `True`). |
| `single_use` | Reject a second use of the same `txn` on this route (needs `replay_store`). |
| `agents` | `pytrat.policy.AgentRequirements` for agent-mediated requests. |
| `policy_id` | Name used in audit and replay keys (inline), or the YAML resource to use (alone). |
| `operation` | Correlation label passed to the enforcer; not an authorization input. |

Misconfiguration raises `ConfigurationError` immediately (bad inline arguments) or at startup
(a bound field that is not a field of the route, an unresolvable `policy_id`, a YAML resource
with `require_transaction: false`). A route never silently runs without its checks.

!!! note "Bind the values the handler receives"
    Bound fields are read with FastAPI's own validators from the same request, so `tctx` is
    compared with exactly what your handler gets. Use strict models: a lax model would coerce
    `"10000"` to `10000` for both. A body that fails validation is reported as
    `422 REQUEST_MALFORMED` only *after* the token and caller have been checked, so an
    unauthenticated client never learns which bound value was wrong.

## The `Transaction` object

| Attribute | Value |
|---|---|
| `txn.id` | The `txn` claim. |
| `txn.subject` | The `sub` claim. |
| `txn.scope` | The token's `Scope`. |
| `txn.tctx` | The verified transaction context (read-only mapping) or `None`. |
| `txn.claims` | All verified claims (`TransactionClaims`). |
| `txn.caller` | The authenticated `WorkloadIdentity` (`id`, `method`), or `None`. |
| `txn.policy_id` | The policy that authorized the request. |
| `txn.binding` | Which `tctx` fields were checked and which `Derived` transforms ran. |
| `txn.token` | The `VerifiedToken`, for forwarding only. |

While the handler runs, the verified token is bound to the request context, so an
`AsyncTransactionClient` forwards it unchanged; see [Client and propagation](client.md).

## Fail closed: protected prefixes and exemptions

With `protected_prefixes=("/internal",)`, every route at or under `/internal` must use
`require_transaction` or be marked `@pytrat.exempt`:

* at startup, `pytrat.lifespan` refuses to start and lists the unguarded routes
  (`POLICY_NOT_FOUND`); `pytrat.unprotected_routes(app)` returns them for your own checks;
* at runtime, the middleware is a backstop: for a request under a protected prefix that did not
  pass through the dependency (a route added after startup, a mounted sub-application), it
  replaces the response with `403 POLICY_NOT_FOUND`. The handler has already run by then, which
  is why the startup check is the primary defence.

```python
--8<-- "docs/snippets/fastapi_extras.py:exempt"
```

## Errors

Every `PyTraTError` is rendered as `application/problem+json`:

```json
{
  "type": "urn:pytrat:problem:TRANSACTION_CONTEXT_MISMATCH",
  "title": "Transaction not authorized",
  "status": 403,
  "reason_code": "TRANSACTION_CONTEXT_MISMATCH",
  "transaction_id": "01a1e862-…"
}
```

`transaction_id` appears only once the token has been verified. `detail` (the name of the failed
check, never a value) is added only with `debug=True`. The full list of codes is in
[Errors and reason codes](errors.md).

## Initiating a transaction at the edge

The trusted edge exchanges the caller's access token for a Txn-Token and binds it for the calls
it makes on the caller's behalf. Do it after the body is validated, so `request_details` (which
the TTS turns into `tctx`) is exactly what the handler acts on:

```python
--8<-- "docs/snippets/fastapi_edge.py"
```

`initiate_transaction` reads the subject token with `bearer_token` by default (exactly one
`Authorization: Bearer` header, otherwise `401 SUBJECT_TOKEN_INVALID`); pass
`extract_subject_token=` to read it elsewhere. The access token is wrapped in a `SecretToken` from
the moment it is read. How to build the two clients is in [Client and propagation](client.md).

## Loading keys from the TTS

Instead of a static JWKS file, fetch the TTS's published keys from a pinned URL:

```python
--8<-- "docs/snippets/client_usage.py:verifier"
```

Pass the refresher as `PyTraT(verifier=verifier, jwks_refresher=jwks, ...)`: keys are loaded at
startup, refreshed when stale (`ttl`), refetched (rate-limited) when a token names an unknown
`kid`. The verify path itself never does I/O. If refreshes keep failing, the last good key set
is used for at most `max_stale` (default 30 minutes); after that every token is rejected with
`KEY_UNKNOWN`.

## Agents

Inline agent constraints use `pytrat.policy.AgentRequirements`:

```python
--8<-- "docs/snippets/fastapi_extras.py:agents"
```

See [Agents](agents.md) for what each constraint means.
