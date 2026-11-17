# pytrat-django

Django integration for PyTraT (OAuth Transaction Tokens): a
`@require_transaction` view decorator (sync and async views), fail-closed middleware for protected
path prefixes, and system checks.

```bash
pip install pytrat-django
```

## Configure and decorate

```python
# settings.py
INSTALLED_APPS = [..., "pytrat.django"]
MIDDLEWARE = [..., "pytrat.django.middleware.TransactionMiddleware"]
PYTRAT = {
    "ENFORCER": "ledger.security.build_enforcer",  # zero-arg factory -> TransactionEnforcer
    "PROTECTED_PREFIXES": ["/internal/"],
}
```

```python
# views.py
from pytrat.django import require_transaction


@require_transaction(
    scope="payments.transfer",
    bind_fields=["source_account", "destination_account", "amount_minor", "currency"],
    allowed_callers=["payment-service"],
)
def record_entry(request):
    txn = request.transaction  # verified; the token is bound for outbound calls
    ...
```

Undecorated views under a protected prefix are denied before they run (`403 POLICY_NOT_FOUND`) and
reported by `manage.py check` (`pytrat.E001`). Unknown `PYTRAT` keys are rejected at startup.

## Documentation

PyTraT documentation: *Django* and the `pytrat.django` API reference (sources in `docs/` of the
repository).

Apache-2.0.
