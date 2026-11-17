from pathlib import Path

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.urls import path
from pydantic import BaseModel, ConfigDict

from pytrat.core import (
    LoggingSink,
    StaticKeySet,
    TokenVerifier,
    VerifierSettings,
    WorkloadJwtAuthenticator,
    WorkloadKeys,
)
from pytrat.django import exempt, require_transaction
from pytrat.policy import Transaction, TransactionEnforcer

KEYS = Path("/etc/pytrat")

# --8<-- [start:settings]
# settings.py
INSTALLED_APPS = [
    # ...
    "pytrat.django",
]
MIDDLEWARE = [
    # ...
    "pytrat.django.middleware.TransactionMiddleware",  # forgotten decorators fail closed
]
PYTRAT = {
    "ENFORCER": "ledger.security.build_enforcer",  # zero-argument factory, called once
    "POLICY": "policy.yaml",  # optional: YAML resources, selected with policy_id=
    "PROTECTED_PREFIXES": ["/internal/"],
    "DEBUG_ERRORS": False,  # True adds the failed check's description to 4xx bodies
    "REPLAY_STORE": "ledger.security.build_replay_store",  # for `single_use` YAML resources
}
# --8<-- [end:settings]


# --8<-- [start:enforcer]
# ledger/security.py
def build_enforcer(keys: Path = KEYS) -> TransactionEnforcer:
    verifier = TokenVerifier(
        VerifierSettings(trust_domain="payments.internal", algorithms=frozenset({"ES256"})),
        StaticKeySet.from_jwks_file(keys / "tts.jwks.json"),
    )
    callers = WorkloadKeys(
        {"payment-service": StaticKeySet.from_jwks_file(keys / "payment-service.jwks.json")}
    )
    return TransactionEnforcer(
        service="ledger-service",
        verify=verifier,
        authenticator=WorkloadJwtAuthenticator(callers, audience="ledger-service"),
        audit=LoggingSink(),  # one JSON line per decision on the "pytrat.audit" logger
    )


# --8<-- [end:enforcer]


# --8<-- [start:views]
# ledger/views.py
class Transfer(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    source_account: str
    destination_account: str
    amount_minor: int
    currency: str


@require_transaction(
    scope="payments.transfer",
    bind_fields=["source_account", "destination_account", "amount_minor", "currency"],
    allowed_callers=["payment-service"],
    body_model=Transfer,  # strict JSON body validation; exposed as request.validated_body
)
def record_entry(request: HttpRequest) -> HttpResponse:
    txn: Transaction = request.transaction
    transfer: Transfer = request.validated_body
    return JsonResponse({"txn": txn.id, "amount_minor": transfer.amount_minor}, status=201)


@require_transaction(policy_id="account-read")  # the YAML resource with this name
async def account(request: HttpRequest, account_id: str) -> HttpResponse:
    return JsonResponse({"account": account_id, "txn": request.transaction.id})


@exempt  # deliberately unguarded under a protected prefix
def healthz(request: HttpRequest) -> HttpResponse:
    return JsonResponse({"status": "ok"})


urlpatterns = [
    path("internal/ledger/entries", record_entry),
    path("internal/accounts/<str:account_id>", account),
    path("internal/healthz", healthz),
]
# --8<-- [end:views]
