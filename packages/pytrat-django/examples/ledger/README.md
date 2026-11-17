# Ledger example (Django)

A minimal Django service protected by `pytrat-django`.

- `POST /internal/transfer` uses the YAML policy `ledger-transfer` and a Pydantic `body_model`,
  so the values compared with `tctx` are exactly the values the view uses.
- `GET /internal/accounts/<source_account>/balance` is an async view with an inline policy that
  binds the URL parameter.
- `GET /internal/health` is `@exempt`. Any other view under `/internal/` that lacks a
  decorator is denied with 403 `POLICY_NOT_FOUND`, and `manage.py check` reports it.

## Run

```bash
export LEDGER_TTS_JWKS=/path/to/tts-jwks.json            # public keys of your TTS
export LEDGER_WORKLOAD_JWKS=/path/to/workload-jwks.json  # keys that sign caller workload JWTs
cd packages/pytrat-django/examples/ledger
uv run python manage.py check
uv run python manage.py runserver
```

Callers send exactly one `Txn-Token` header and a `Workload-Identity` workload JWT
(`typ: wit+jwt`, `aud: ledger`). Errors are RFC 9457 `application/problem+json`.
