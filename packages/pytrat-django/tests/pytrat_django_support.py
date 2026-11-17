"""Importable test support: enforcer factories, views and the URLconf for the Django tests.

Lives on ``sys.path`` (see conftest) so ``PYTRAT['ENFORCER']`` and ``ROOT_URLCONF`` can name it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from django.apps import apps
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.urls import include, path, re_path
from pydantic import BaseModel, ConfigDict

from pytrat.client.context import current_transaction
from pytrat.core import (
    DependencyError,
    InMemoryReplayStore,
    MemorySink,
    WorkloadJwtAuthenticator,
    WorkloadKeys,
)
from pytrat.core.crypto import sign_compact
from pytrat.core.testing import TestKey, TokenFactory, generate_test_key
from pytrat.django import exempt, require_transaction
from pytrat.policy import TransactionEnforcer

POLICY_PATH = Path(__file__).with_name("policy.yaml")
SERVICE = "ledger"
CALLERS = ("payment-service", "api-gateway", "intruder", "intruder-service", "reporting-service")
TRANSFER_FIELDS = ["source_account", "destination_account", "amount_minor", "currency"]


@dataclass
class World:
    """Keys, sink and enforcer for one test."""

    factory: TokenFactory = field(default_factory=TokenFactory.create)
    caller_keys: dict[str, TestKey] = field(
        default_factory=lambda: {
            name: generate_test_key("ES256", kid=f"{name}-key") for name in CALLERS
        }
    )
    sink: MemorySink = field(default_factory=MemorySink)

    @property
    def caller_key(self) -> TestKey:
        return self.caller_keys["payment-service"]

    def enforcer(self) -> TransactionEnforcer:
        return TransactionEnforcer(
            service=SERVICE,
            verify=self.factory.verifier(),
            authenticator=WorkloadJwtAuthenticator(
                WorkloadKeys({name: key.key_set() for name, key in self.caller_keys.items()}),
                audience=SERVICE,
                clock=self.factory.clock,
            ),
            audit=self.sink,
        )

    def workload_jwt(self, subject: str = "payment-service", key: TestKey | None = None) -> str:
        signer = key or self.caller_keys.get(subject, self.caller_key)
        now = int(self.factory.clock.now())
        return sign_compact(
            {"sub": subject, "aud": SERVICE, "iat": now, "exp": now + 60},
            signer.private_key,
            alg=signer.alg,
            kid=signer.kid,
            typ="wit+jwt",
        )


CURRENT: dict[str, World] = {"world": World()}

TEST_SETTINGS: dict[str, object] = {
    "PYTRAT": {
        "ENFORCER": "pytrat_django_support.build_enforcer",
        "POLICY": str(POLICY_PATH),
        "PROTECTED_PREFIXES": ["/internal/"],
        "DEBUG_ERRORS": False,
    },
    "ROOT_URLCONF": "pytrat_django_support",
    "MIDDLEWARE": ["pytrat.django.middleware.TransactionMiddleware"],
}


def pytrat_settings(**overrides: object) -> dict[str, object]:
    base = TEST_SETTINGS["PYTRAT"]
    assert isinstance(base, dict)
    return {**base, **overrides}


def reload_runtime() -> None:
    apps.get_app_config("pytrat_django").ready()


def build_enforcer() -> TransactionEnforcer:
    return CURRENT["world"].enforcer()


def not_an_enforcer() -> object:
    return object()


NOT_CALLABLE = 42


def build_replay_store() -> InMemoryReplayStore:
    return InMemoryReplayStore(clock=CURRENT["world"].factory.clock)


class AllowAllAgents:
    def is_registered(self, agent_id: str) -> bool:
        return True


def build_agent_directory() -> AllowAllAgents:
    return AllowAllAgents()


def build_nothing() -> object:
    return object()


def _describe(request: HttpRequest) -> dict[str, object]:
    txn = request.transaction
    bound = current_transaction()
    return {
        "txn": txn.id,
        "caller": txn.caller.id if txn.caller else None,
        "bound_txn": bound.claims.txn,
    }


@require_transaction(
    scope="payments.transfer", bind_fields=TRANSFER_FIELDS, allowed_callers=["payment-service"]
)
def transfer(request: HttpRequest) -> HttpResponse:
    return JsonResponse(_describe(request))


@require_transaction(scope="payments.transfer", bind_fields=TRANSFER_FIELDS)
async def async_transfer(request: HttpRequest) -> HttpResponse:
    return JsonResponse(_describe(request))


class Transfer(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    source_account: str
    destination_account: str
    amount_minor: int
    currency: str
    memo: str = ""


SEEN: dict[str, object] = {}


@require_transaction(scope="payments.transfer", bind_fields=TRANSFER_FIELDS, body_model=Transfer)
def model_transfer(request: HttpRequest) -> HttpResponse:
    body = request.validated_body
    SEEN["body"] = body
    return JsonResponse({"amount_minor": body.amount_minor, **_describe(request)})


@require_transaction(scope="payments.transfer", bind_fields=["source_account"])
def account_transfer(request: HttpRequest, source_account: str) -> HttpResponse:
    return JsonResponse({"source_account": source_account, **_describe(request)})


@require_transaction(scope="payments.read", require_workload_identity=False)
def no_binding(request: HttpRequest) -> HttpResponse:
    return JsonResponse(_describe(request))


@require_transaction(policy_id="ledger-transfer")
def yaml_transfer(request: HttpRequest) -> HttpResponse:
    return JsonResponse(_describe(request))


@require_transaction(policy_id="ledger-callers-only")
def yaml_callers_only(request: HttpRequest) -> HttpResponse:
    return JsonResponse({"transaction": request.transaction is None})


@require_transaction(policy_id="does-not-exist")
def unknown_policy(request: HttpRequest) -> HttpResponse:  # pragma: no cover - never runs
    return HttpResponse("unreachable")


@require_transaction(scope="payments.transfer", bind_fields=TRANSFER_FIELDS)
def view_raises(request: HttpRequest) -> HttpResponse:
    raise DependencyError("downstream unavailable")


@require_transaction(scope="payments.transfer", bind_fields=TRANSFER_FIELDS)
async def async_view_raises(request: HttpRequest) -> HttpResponse:
    raise DependencyError("downstream unavailable")


def forgotten(request: HttpRequest) -> HttpResponse:
    return HttpResponse("this must never be served")


async def async_forgotten(request: HttpRequest) -> HttpResponse:
    return HttpResponse("this must never be served")


@exempt
def health(request: HttpRequest) -> HttpResponse:
    return HttpResponse("ok")


def public(request: HttpRequest) -> HttpResponse:
    return HttpResponse("public")


nested = [path("forgotten", forgotten), path("health", health)]

urlpatterns = [
    path("internal/transfer", transfer),
    path("internal/async-transfer", async_transfer),
    path("internal/model-transfer", model_transfer),
    path("internal/accounts/<str:source_account>/transfer", account_transfer),
    path("internal/no-binding", no_binding),
    path("internal/yaml-transfer", yaml_transfer),
    path("internal/yaml-callers-only", yaml_callers_only),
    path("internal/unknown-policy", unknown_policy),
    path("internal/view-raises", view_raises),
    path("internal/async-view-raises", async_view_raises),
    path("internal/forgotten", forgotten),
    path("internal/async-forgotten", async_forgotten),
    path("internal/health", health),
    path("internal/nested/", include(nested)),
    re_path(r"^internal/legacy$", forgotten),
    path("public/hello", public),
]
