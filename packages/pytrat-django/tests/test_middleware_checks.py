from __future__ import annotations

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.test import AsyncClient
from django.test.utils import override_settings

import pytrat_django_support as support
from pytrat.core import ReasonCode
from pytrat.django import TransactionMiddleware, check_routes, exempt, require_transaction
from pytrat.django.decorators import guard_of, is_exempt


def problem_reason(response) -> str:
    assert response["Content-Type"] == "application/problem+json"
    return response.json()["reason_code"]


@pytest.mark.parametrize(
    "url", ["/internal/forgotten", "/internal/nested/forgotten", "/internal/legacy"]
)
def test_undecorated_protected_view_is_denied(client, url) -> None:
    response = client.get(url)
    assert response.status_code == 403
    assert problem_reason(response) == ReasonCode.POLICY_NOT_FOUND
    assert b"never be served" not in response.content


async def test_undecorated_async_view_is_denied_under_asgi(async_client: AsyncClient) -> None:
    response = await async_client.get("/internal/async-forgotten")
    assert response.status_code == 403
    assert problem_reason(response) == ReasonCode.POLICY_NOT_FOUND


async def test_middleware_passes_through_under_asgi(async_client: AsyncClient) -> None:
    response = await async_client.get("/public/hello")
    assert response.status_code == 200


@pytest.mark.parametrize("url", ["/internal/health", "/internal/nested/health"])
def test_exempt_view_is_served(client, url) -> None:
    response = client.get(url)
    assert response.status_code == 200
    assert response.content == b"ok"


def test_view_outside_protected_prefix_is_served(client) -> None:
    assert client.get("/public/hello").status_code == 200


def test_middleware_is_sync_and_async_capable() -> None:
    assert TransactionMiddleware.sync_capable
    assert TransactionMiddleware.async_capable


def test_markers() -> None:
    assert guard_of(support.transfer) is not None
    assert guard_of(support.forgotten) is None
    assert is_exempt(support.health)
    assert not is_exempt(support.transfer)


def test_decorator_order_with_exempt_is_preserved() -> None:
    @exempt
    def view(request):  # pragma: no cover - never called
        return None

    assert is_exempt(view)


def ids(messages) -> list[str]:
    return [message.id for message in messages]


def test_check_reports_undecorated_protected_views() -> None:
    messages = check_routes()
    errors = [m for m in messages if m.id == "pytrat.E001"]
    routes = sorted(m.msg.split("'")[1] for m in errors)
    assert routes == [
        "/internal/async-forgotten",
        "/internal/forgotten",
        "/internal/legacy",
        "/internal/nested/forgotten",
    ]


def test_check_reports_unknown_policy_id() -> None:
    messages = [m for m in check_routes() if m.id == "pytrat.E002"]
    assert len(messages) == 1
    assert "does-not-exist" in messages[0].msg


def test_check_warns_when_middleware_missing() -> None:
    with override_settings(MIDDLEWARE=[]):
        assert "pytrat.W001" in ids(check_routes())
    assert "pytrat.W001" not in ids(check_routes())


def test_check_reports_uninitialised_runtime() -> None:
    from django.apps import apps

    config = apps.get_app_config("pytrat_django")
    saved, config.runtime = config.runtime, None
    try:
        assert ids(check_routes()) == ["pytrat.E000"]
    finally:
        config.runtime = saved


def test_check_without_protected_prefixes_ignores_undecorated_views() -> None:
    with override_settings(PYTRAT=support.pytrat_settings(PROTECTED_PREFIXES=[])):
        support.reload_runtime()
        assert "pytrat.E001" not in ids(check_routes())


def test_decorator_requires_scope_or_policy_id() -> None:
    with pytest.raises(ImproperlyConfigured, match="scope"):
        require_transaction()


def test_decorator_rejects_policy_id_with_inline_arguments() -> None:
    with pytest.raises(ImproperlyConfigured, match="not both"):
        require_transaction(policy_id="x", scope="payments.transfer")


def test_decorator_rejects_invalid_inline_policy_at_decoration_time() -> None:
    decorate = require_transaction(scope="payments.transfer", single_use=True)
    with pytest.raises(ImproperlyConfigured, match="replay store"):
        decorate(support.public)


def test_decorator_accepts_single_use_with_replay_store() -> None:
    decorated = require_transaction(
        scope="payments.transfer", single_use=True, replay_store=support.build_replay_store()
    )(support.public)
    guard = guard_of(decorated)
    assert guard is not None
    assert guard.policy is not None
    assert guard.policy.single_use
    assert guard.policy.policy_id == "pytrat_django_support.public"


def test_decorator_names_callable_objects() -> None:
    class Callable:
        def __call__(self, request):  # pragma: no cover - never called
            return None

    decorated = require_transaction(scope="payments.transfer")(Callable())
    guard = guard_of(decorated)
    assert guard is not None
    assert guard.policy is not None
    assert guard.policy.policy_id.endswith("Callable")
