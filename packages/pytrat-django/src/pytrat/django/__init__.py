"""PyTraT Django integration: Transaction Token enforcement for Django views.

Add ``"pytrat.django"`` to ``INSTALLED_APPS`` and configure::

    PYTRAT = {
        "ENFORCER": "myproject.security.build_enforcer",  # zero-arg -> TransactionEnforcer
        "POLICY": "policy.yaml",                           # optional YAML policy
        "PROTECTED_PREFIXES": ["/internal/"],
        "DEBUG_ERRORS": False,
    }
    MIDDLEWARE = [..., "pytrat.django.middleware.TransactionMiddleware"]

then decorate views::

    @require_transaction(scope="payments.transfer", bind_fields=["amount_minor", "currency"])
    def transfer(request):
        txn = request.transaction
        ...
"""

from pytrat.django._http import (
    BodyValidationError,
    RequestDataError,
    UnsupportedBodyError,
    inbound_request,
    problem_response,
)
from pytrat.django._runtime import Runtime, get_enforcer, get_runtime
from pytrat.django._settings import PyTraTSettings, parse_settings
from pytrat.django.checks import check_routes
from pytrat.django.decorators import TransactionGuard, exempt, require_transaction
from pytrat.django.middleware import TransactionMiddleware

__all__ = [
    "BodyValidationError",
    "PyTraTSettings",
    "RequestDataError",
    "Runtime",
    "TransactionGuard",
    "TransactionMiddleware",
    "UnsupportedBodyError",
    "check_routes",
    "exempt",
    "get_enforcer",
    "get_runtime",
    "inbound_request",
    "parse_settings",
    "problem_response",
    "require_transaction",
]
