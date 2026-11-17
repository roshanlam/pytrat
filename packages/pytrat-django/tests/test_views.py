from __future__ import annotations

import json

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.test import AsyncClient, Client, RequestFactory
from django.test.utils import override_settings

import pytrat_django_support as support
from pytrat.client.context import optional_transaction
from pytrat.core import EventType, ReasonCode
from pytrat.django import inbound_request

TCTX = {
    "source_account": "account-A",
    "destination_account": "account-B",
    "amount_minor": 10000,
    "currency": "USD",
}


def headers(world: support.World, *, token: object = ..., caller: str | None = "ok"):
    result: dict[str, str] = {}
    if token is ...:
        token = world.factory.mint(txn="txn-1")
    if token is not None:
        result["Txn-Token"] = token
    if caller == "ok":
        caller = world.workload_jwt()
    if caller is not None:
        result["Workload-Identity"] = caller
    return result


def post(client: Client, url: str, body: object, hdrs: dict[str, str], **kwargs):
    data = body if isinstance(body, str | bytes) else json.dumps(body)
    content_type = kwargs.pop("content_type", "application/json")
    return client.post(url, data=data, content_type=content_type, headers=hdrs, **kwargs)


def assert_problem(response, status: int, reason: ReasonCode) -> dict[str, object]:
    assert response.status_code == status
    assert response["Content-Type"] == "application/problem+json"
    body = response.json()
    assert body["reason_code"] == reason.value
    assert body["status"] == status
    return body


# ------------------------------------------------------------------ happy paths


def test_legitimate_request_is_authorized_and_bound(client, world) -> None:
    response = post(client, "/internal/transfer", TCTX, headers(world))
    assert response.status_code == 200
    assert response.json() == {"txn": "txn-1", "caller": "payment-service", "bound_txn": "txn-1"}
    [event] = world.sink.events
    assert event.event_type is EventType.AUTHORIZATION_GRANTED
    assert event.caller_workload == "payment-service"
    # The context binding does not outlive the view.
    assert optional_transaction() is None


async def test_async_view_is_authorized_and_bound(async_client: AsyncClient, world) -> None:
    response = await async_client.post(
        "/internal/async-transfer",
        data=json.dumps(TCTX),
        content_type="application/json",
        headers=headers(world),
    )
    assert response.status_code == 200
    assert response.json()["bound_txn"] == "txn-1"


async def test_async_view_denies_tampered_request(async_client: AsyncClient, world) -> None:
    response = await async_client.post(
        "/internal/async-transfer",
        data=json.dumps({**TCTX, "amount_minor": 99999}),
        content_type="application/json",
        headers=headers(world),
    )
    assert_problem(response, 403, ReasonCode.TRANSACTION_CONTEXT_MISMATCH)


def test_async_view_runs_under_sync_client(client, world) -> None:
    response = post(client, "/internal/async-transfer", TCTX, headers(world))
    assert response.status_code == 200


def test_url_kwargs_are_bound(client, world) -> None:
    response = post(client, "/internal/accounts/account-A/transfer", {}, headers(world))
    assert response.status_code == 200
    assert response.json()["source_account"] == "account-A"


def test_tampered_url_kwarg_is_rejected(client, world) -> None:
    response = post(client, "/internal/accounts/account-EVIL/transfer", {}, headers(world))
    assert_problem(response, 403, ReasonCode.TRANSACTION_CONTEXT_MISMATCH)


def test_query_parameters_are_bound(client, world) -> None:
    response = post(client, "/internal/accounts/account-A/transfer?note=x", {}, headers(world))
    assert response.status_code == 200


def test_yaml_policy_by_id(client, world) -> None:
    response = post(client, "/internal/yaml-transfer", TCTX, headers(world))
    assert response.status_code == 200
    assert world.sink.events[0].policy_id == "ledger-transfer"


def test_yaml_policy_without_transaction_sets_none(client, world) -> None:
    response = client.get("/internal/yaml-callers-only", headers=headers(world, token=None))
    assert response.status_code == 200
    assert response.json() == {"transaction": True}


def test_policy_without_binding_ignores_form_body(client, world) -> None:
    token = world.factory.mint(txn="txn-1", scope="payments.read")
    response = client.post(
        "/internal/no-binding", data={"field": "value"}, headers={"Txn-Token": token}
    )
    assert response.status_code == 200


# ------------------------------------------------------------------ attacks


def test_tampered_amount_is_rejected_and_audited(client, world) -> None:
    response = post(client, "/internal/transfer", {**TCTX, "amount_minor": 99999}, headers(world))
    body = assert_problem(response, 403, ReasonCode.TRANSACTION_CONTEXT_MISMATCH)
    assert "detail" not in body
    [event] = world.sink.events
    assert event.event_type is EventType.AUTHORIZATION_DENIED
    assert event.reason_code is ReasonCode.TRANSACTION_CONTEXT_MISMATCH


def test_missing_token_is_401_with_challenge(client, world) -> None:
    response = post(client, "/internal/transfer", TCTX, headers(world, token=None))
    assert_problem(response, 401, ReasonCode.TOKEN_MISSING)
    assert response["WWW-Authenticate"] == "Txn-Token"
    [event] = world.sink.events
    assert event.event_type is EventType.TOKEN_REJECTED


def test_comma_joined_duplicate_token_is_rejected(client, world) -> None:
    """txn-tokens-11 §12.1: WSGI joins repeated headers; a comma means two tokens were sent."""
    first, second = world.factory.mint(), world.factory.mint()
    response = post(client, "/internal/transfer", TCTX, headers(world, token=f"{first},{second}"))
    assert_problem(response, 401, ReasonCode.TOKEN_MALFORMED)


def test_trailing_comma_token_is_rejected(client, world) -> None:
    token = world.factory.mint()
    response = post(client, "/internal/transfer", TCTX, headers(world, token=f"{token},"))
    assert_problem(response, 401, ReasonCode.TOKEN_MALFORMED)


def test_wrong_caller_is_rejected(client, world) -> None:
    hdrs = headers(world, caller=world.workload_jwt("intruder-service"))
    response = post(client, "/internal/transfer", TCTX, hdrs)
    assert_problem(response, 403, ReasonCode.CALLER_NOT_ALLOWED)


def test_missing_workload_credential_is_401(client, world) -> None:
    response = post(client, "/internal/transfer", TCTX, headers(world, caller=None))
    assert_problem(response, 401, ReasonCode.WORKLOAD_UNAUTHENTICATED)
    assert response["WWW-Authenticate"] == "Txn-Token"


def test_workload_credential_from_untrusted_key_is_401(client, world) -> None:
    rogue = support.generate_test_key()
    hdrs = headers(world, caller=world.workload_jwt(key=rogue))
    response = post(client, "/internal/transfer", TCTX, hdrs)
    assert_problem(response, 401, ReasonCode.WORKLOAD_UNAUTHENTICATED)


def test_json_with_duplicate_keys_is_400(client, world) -> None:
    raw = (
        '{"source_account": "account-A", "destination_account": "account-B",'
        ' "amount_minor": 10000, "amount_minor": 99999, "currency": "USD"}'
    )
    response = post(client, "/internal/transfer", raw, headers(world))
    assert_problem(response, 400, ReasonCode.REQUEST_MALFORMED)
    assert world.sink.events == []


@pytest.mark.parametrize("raw", ["[1, 2]", "not json", '{"a": NaN}'])
def test_non_object_or_invalid_json_is_400(client, world, raw) -> None:
    response = post(client, "/internal/transfer", raw, headers(world))
    assert_problem(response, 400, ReasonCode.REQUEST_MALFORMED)


def test_bound_body_must_be_json(client, world) -> None:
    response = client.post("/internal/transfer", data=TCTX, headers=headers(world))
    assert_problem(response, 415, ReasonCode.REQUEST_MALFORMED)


def test_body_and_url_kwarg_collision_is_400(client, world) -> None:
    body = {"source_account": "account-A"}
    response = post(client, "/internal/accounts/account-A/transfer", body, headers(world))
    assert_problem(response, 400, ReasonCode.REQUEST_MALFORMED)


def test_query_shadowing_body_field_is_400(client, world) -> None:
    response = post(client, "/internal/transfer?amount_minor=1", TCTX, headers(world))
    assert_problem(response, 400, ReasonCode.REQUEST_MALFORMED)


def test_repeated_query_parameter_is_400(client, world) -> None:
    response = post(client, "/internal/accounts/account-A/transfer?x=1&x=2", {}, headers(world))
    assert_problem(response, 400, ReasonCode.REQUEST_MALFORMED)


# ------------------------------------------------------------------ body_model


def test_body_model_binding_matches_what_the_view_sees(client, world) -> None:
    response = post(client, "/internal/model-transfer", {**TCTX, "memo": "rent"}, headers(world))
    assert response.status_code == 200
    seen = support.SEEN.pop("body")
    assert isinstance(seen, support.Transfer)
    assert seen.amount_minor == 10000
    assert seen.memo == "rent"


def test_body_model_rejects_tampered_amount(client, world) -> None:
    response = post(client, "/internal/model-transfer", {**TCTX, "amount_minor": 1}, headers(world))
    assert_problem(response, 403, ReasonCode.TRANSACTION_CONTEXT_MISMATCH)


def test_body_model_validation_failure_is_422(client, world) -> None:
    response = post(
        client, "/internal/model-transfer", {**TCTX, "amount_minor": "10000"}, headers(world)
    )
    assert_problem(response, 422, ReasonCode.REQUEST_MALFORMED)


def test_body_model_requires_json(client, world) -> None:
    response = client.post("/internal/model-transfer", headers=headers(world))
    assert_problem(response, 415, ReasonCode.REQUEST_MALFORMED)


# ------------------------------------------------------------------ errors from views


def test_pytrat_error_from_view_carries_transaction_id(client, world) -> None:
    response = post(client, "/internal/view-raises", TCTX, headers(world))
    body = assert_problem(response, 503, ReasonCode.DEPENDENCY_UNAVAILABLE)
    assert body["transaction_id"] == "txn-1"


async def test_pytrat_error_from_async_view(async_client: AsyncClient, world) -> None:
    response = await async_client.post(
        "/internal/async-view-raises",
        data=json.dumps(TCTX),
        content_type="application/json",
        headers=headers(world),
    )
    assert_problem(response, 503, ReasonCode.DEPENDENCY_UNAVAILABLE)


def test_unknown_policy_id_fails_closed(client, world) -> None:
    with pytest.raises(ImproperlyConfigured):
        post(client, "/internal/unknown-policy", TCTX, headers(world))


def test_policy_id_without_yaml_fails_closed(client, world) -> None:
    with override_settings(PYTRAT=support.pytrat_settings(POLICY=None)):
        support.reload_runtime()
        with pytest.raises(ImproperlyConfigured, match="POLICY"):
            post(client, "/internal/yaml-transfer", TCTX, headers(world))


# ------------------------------------------------------------------ problem+json shape


def test_problem_json_shape(client, world) -> None:
    response = post(client, "/internal/transfer", TCTX, headers(world, token=None))
    assert response.json() == {
        "type": "urn:pytrat:problem:TOKEN_MISSING",
        "title": "Invalid transaction token",
        "status": 401,
        "reason_code": "TOKEN_MISSING",
    }
    assert response["WWW-Authenticate"] == "Txn-Token"


def test_denial_after_verification_reports_transaction_id(client, world) -> None:
    token = world.factory.mint(txn="txn-77")
    response = post(
        client, "/internal/transfer", {**TCTX, "amount_minor": 1}, headers(world, token=token)
    )
    assert (
        assert_problem(response, 403, ReasonCode.TRANSACTION_CONTEXT_MISMATCH)["transaction_id"]
        == "txn-77"
    )


def test_debug_errors_adds_detail_without_secrets(client, world) -> None:
    token = world.factory.mint()
    with override_settings(PYTRAT=support.pytrat_settings(DEBUG_ERRORS=True)):
        support.reload_runtime()
        response = post(
            client, "/internal/transfer", {**TCTX, "amount_minor": 1}, headers(world, token=token)
        )
    body = assert_problem(response, 403, ReasonCode.TRANSACTION_CONTEXT_MISMATCH)
    assert isinstance(body["detail"], str)
    assert token not in response.content.decode()
    assert "99999" not in body["detail"]


# ------------------------------------------------------------------ inbound conversion


def test_inbound_request_maps_meta_to_headers() -> None:
    request = RequestFactory().post(
        "/x",
        data="{}",
        content_type="application/json",
        headers={"Txn-Token": "a.b.c", "Workload-Identity": "w"},
        REMOTE_ADDR="10.0.0.1",
    )
    inbound = inbound_request(request)
    assert inbound.single("txn-token") == "a.b.c"
    assert inbound.single("Workload-Identity") == "w"
    assert inbound.single("Content-Type") == "application/json"
    assert inbound.peer == "10.0.0.1"


def test_inbound_request_without_peer() -> None:
    request = RequestFactory().get("/x", REMOTE_ADDR="")
    request.META["wsgi.something"] = object()
    assert inbound_request(request).peer is None


# ------------------------------------------------------------------ consumed request streams


def test_multipart_body_already_parsed_is_not_bindable(world) -> None:
    request = RequestFactory().post("/internal/transfer", data=TCTX, headers=headers(world))
    assert request.POST["currency"] == "USD"  # consumes the stream
    response = support.transfer(request)
    assert response.status_code == 415


def test_json_body_already_read_is_rejected(world) -> None:
    request = RequestFactory().post(
        "/internal/transfer",
        data=json.dumps(TCTX),
        content_type="application/json",
        headers=headers(world),
    )
    request.read()
    response = support.transfer(request)
    assert response.status_code == 400
    assert world.sink.events == []


def test_problem_response_uses_shared_core_document() -> None:
    from pytrat.core import ConfigurationError, problem_details
    from pytrat.django import problem_response

    error = ConfigurationError("bad")
    response = problem_response(error, transaction_id="txn-7")
    assert response.status_code == 500
    body = json.loads(response.content)
    assert body == problem_details(error)
    assert body["type"] == "urn:pytrat:problem:POLICY_INVALID"
    assert body["transaction_id"] == "txn-7"
