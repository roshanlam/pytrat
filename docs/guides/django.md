# Django

`pytrat-django` provides a `@require_transaction` view decorator (sync and async views), a
fail-closed middleware and system checks. It runs the same `TransactionEnforcer` pipeline as the
FastAPI integration, so decisions, reason codes and audit events are identical.

```bash
uv add pytrat-django
```

## Settings

```python
--8<-- "docs/snippets/django_app.py:settings"
```

The `PYTRAT` setting is validated when the app loads (`AppConfig.ready()`); an unknown key or a
wrong type raises `ImproperlyConfigured`, so a typo can never silently drop a protection.

| Key | Required | Meaning |
|---|---|---|
| `ENFORCER` | yes | Dotted path to a zero-argument factory returning a `pytrat.policy.TransactionEnforcer`. Called once at startup. |
| `POLICY` | no | Path to a YAML policy file. Views select resources with `@require_transaction(policy_id=...)`. |
| `PROTECTED_PREFIXES` | no | URL path prefixes whose views must be decorated with `@require_transaction` or `@exempt`. |
| `DEBUG_ERRORS` | no | `True` adds the failed check's `detail` (never values) to problem responses. Default `False`. |
| `REPLAY_STORE` | no | Dotted path to a zero-argument `ReplayStore` factory, used by YAML resources with `single_use: true`. |
| `AGENT_DIRECTORY` | no | Dotted path to a zero-argument `AgentDirectory` factory, used by YAML resources with `require_verified_agent`. |

## The enforcer factory

The factory decides how tokens are verified, how callers are authenticated and where audit events
go:

```python
--8<-- "docs/snippets/django_app.py:enforcer"
```

## Decorating views

```python
--8<-- "docs/snippets/django_app.py:views"
```

`@require_transaction` takes the same inline arguments as the FastAPI dependency (`scope`,
`bind_fields`, `allowed_callers`, `require_workload_identity`, `single_use`, `agents`), compiled
once at decoration time, or `policy_id=` alone to use a YAML resource. Additionally:

| Argument | Meaning |
|---|---|
| `body_model` | A Pydantic model the JSON body is validated against. The instance is `request.validated_body`, and its `model_dump(mode="python")` is what gets bound. |
| `operation` | Operation name passed to the policy (correlation only). |
| `replay_store` | Replay store for inline `single_use=True`. |
| `agent_directory` | Directory for inline `agents.require_verified_agent`. |

Per request the decorator builds the request data from the strict JSON body, the URL kwargs and
the query parameters (a name present in two of those sources is a `400`), runs the enforcer, sets
`request.transaction` and binds the token while the view runs, so outbound `TransactionClient`
calls propagate it. Any `PyTraTError`, including one raised by the view, becomes an RFC 9457
problem response.

Unlike the FastAPI integration, Django honours YAML resources with `require_transaction: false`:
only the caller is checked and `request.transaction` is `None`.

!!! note "WSGI header joining"
    WSGI servers join repeated headers with commas. A comma in the `Txn-Token` header is therefore
    treated as two tokens and rejected (`TOKEN_MALFORMED`).

## Fail closed

* `TransactionMiddleware` answers `403 POLICY_NOT_FOUND`, **before the view runs**, for any view
  under `PROTECTED_PREFIXES` that is neither decorated nor `@exempt`. It works under WSGI and ASGI.
* System checks (`manage.py check`, also run by `runserver` and `migrate`):

| Check | Meaning |
|---|---|
| `pytrat.E000` | The `PYTRAT` setting or a factory it names is invalid. |
| `pytrat.E001` | A view under a protected prefix has neither `@require_transaction` nor `@exempt`. |
| `pytrat.E002` | A view's `policy_id` is not in the YAML policy. |
| `pytrat.W001` | `PROTECTED_PREFIXES` is set but `TransactionMiddleware` is not installed. |
