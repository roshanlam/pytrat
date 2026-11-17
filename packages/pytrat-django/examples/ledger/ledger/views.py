"""Ledger views: one YAML-policy view, one inline-policy view and an exempt health check."""

from django.http import HttpRequest, HttpResponse, JsonResponse
from pydantic import BaseModel, ConfigDict

from pytrat.django import exempt, require_transaction


class Transfer(BaseModel):
    """The transfer body; bound to ``tctx`` exactly as validated."""

    model_config = ConfigDict(strict=True, extra="forbid")

    source_account: str
    destination_account: str
    amount_minor: int
    currency: str


@require_transaction(policy_id="ledger-transfer", body_model=Transfer)
def transfer(request: HttpRequest) -> HttpResponse:
    """Record a transfer that matches the authorized transaction context."""
    body: Transfer = request.validated_body
    return JsonResponse({"txn": request.transaction.id, "recorded": body.amount_minor})


@require_transaction(
    scope="payments.read",
    bind_fields=["source_account"],
    allowed_callers=["payment-service"],
)
async def balance(request: HttpRequest, source_account: str) -> HttpResponse:
    """Return a balance for the account the transaction was authorized for."""
    return JsonResponse({"account": source_account, "balance_minor": 0})


@exempt
def health(request: HttpRequest) -> HttpResponse:
    """Liveness probe; deliberately unprotected."""
    return HttpResponse("ok")
