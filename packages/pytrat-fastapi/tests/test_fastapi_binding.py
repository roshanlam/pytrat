"""Body, path and query binding: what is compared with tctx is exactly what the handler gets."""

from typing import Annotated

import pytest
from fastapi import APIRouter, Body, Depends, FastAPI
from pydantic import BaseModel

from _fastapi_testkit import TCTX, Kit, StrictTransfer, Transfer, ledger_app, serve
from pytrat.core import ConfigurationError, Derived, ReasonCode
from pytrat.fastapi import Transaction

BODY = dict(TCTX)


async def test_handler_values_and_bound_values_are_identical(kit: Kit) -> None:
    pytrat = kit.pytrat()
    app, seen = ledger_app(pytrat)
    async with serve(app, pytrat) as client:
        response = await client.post("/internal/transfer", json=BODY, headers=kit.headers())
    assert response.status_code == 200
    assert seen["body"] == TCTX
    assert {k: type(v) for k, v in seen["body"].items()} == {k: type(v) for k, v in TCTX.items()}


async def test_string_amount_is_coerced_identically_for_binding_and_handler(kit: Kit) -> None:
    """A lax model turns "10000" into 10000 for the handler; binding sees the same int."""
    pytrat = kit.pytrat()
    app, seen = ledger_app(pytrat)
    async with serve(app, pytrat) as client:
        response = await client.post(
            "/internal/transfer", json={**BODY, "amount_minor": "10000"}, headers=kit.headers()
        )
    assert response.status_code == 200
    assert seen["body"]["amount_minor"] == 10000
    assert type(seen["body"]["amount_minor"]) is int


async def test_type_juggling_against_a_string_tctx_value_is_rejected(kit: Kit) -> None:
    """tctx says "10000" (str) and so does the raw JSON, but the handler would act on int 10000.

    A comparison against raw JSON would allow this; binding the validated value rejects it.
    """
    pytrat = kit.pytrat()
    app, seen = ledger_app(pytrat)
    async with serve(app, pytrat) as client:
        response = await client.post(
            "/internal/transfer",
            json={**BODY, "amount_minor": "10000"},
            headers=kit.headers(tctx={**TCTX, "amount_minor": "10000"}),
        )
    assert response.status_code == 403
    assert response.json()["reason_code"] == "TRANSACTION_CONTEXT_MISMATCH"
    assert not seen


async def test_strict_model_rejects_string_amount_without_echoing_it(kit: Kit) -> None:
    pytrat = kit.pytrat()
    app, seen = ledger_app(pytrat, model=StrictTransfer)
    async with serve(app, pytrat) as client:
        response = await client.post(
            "/internal/transfer", json={**BODY, "amount_minor": "777777"}, headers=kit.headers()
        )
    assert response.status_code == 422
    assert response.json()["reason_code"] == "REQUEST_MALFORMED"
    assert "777777" not in response.text
    assert not seen


async def test_float_bound_field_is_rejected(kit: Kit) -> None:
    class FloatTransfer(BaseModel):
        amount: float

    pytrat = kit.pytrat()
    app = FastAPI()
    pytrat.install(app)
    dependency = pytrat.require_transaction(scope="payments.transfer", bind_fields=["amount"])

    @app.post("/internal/pay")
    async def pay(body: FloatTransfer, txn: Annotated[Transaction, Depends(dependency)]) -> None:
        raise AssertionError("must not run")

    async with serve(app, pytrat) as client:
        response = await client.post(
            "/internal/pay", json={"amount": 100}, headers=kit.headers(tctx={"amount": 100})
        )
    assert response.status_code == 403
    assert response.json()["reason_code"] == "TRANSACTION_CONTEXT_MISMATCH"


def debit_app(kit: Kit, pytrat, seen: dict[str, object]) -> FastAPI:
    class Debit(BaseModel):
        amount_minor: int

    app = FastAPI()
    pytrat.install(app)
    dependency = pytrat.require_transaction(
        scope="payments.transfer", bind_fields=["account_id", "order", "currency", "amount_minor"]
    )

    @app.post("/internal/accounts/{account_id}/orders/{order}")
    async def debit(
        account_id: str,
        order: int,
        currency: str,
        body: Debit,
        txn: Annotated[Transaction, Depends(dependency)],
    ) -> dict[str, str]:
        seen.update(account_id=account_id, order=order, currency=currency)
        return {"ok": "yes"}

    return app


DEBIT_TCTX = {"account_id": "acct-1", "order": 42, "currency": "USD", "amount_minor": 5}


@pytest.mark.parametrize(
    ("url", "tctx", "status"),
    [
        ("/internal/accounts/acct-1/orders/42?currency=USD", DEBIT_TCTX, 200),
        ("/internal/accounts/acct-2/orders/42?currency=USD", DEBIT_TCTX, 403),
        ("/internal/accounts/acct-1/orders/42?currency=EUR", DEBIT_TCTX, 403),
        ("/internal/accounts/acct-1/orders/42?currency=USD", {**DEBIT_TCTX, "order": "42"}, 403),
    ],
    ids=["match", "tampered-path", "tampered-query", "path-param-type"],
)
async def test_path_and_query_params_are_bound_by_name(kit: Kit, url, tctx, status) -> None:
    pytrat = kit.pytrat()
    seen: dict[str, object] = {}
    app = debit_app(kit, pytrat, seen)
    async with serve(app, pytrat) as client:
        response = await client.post(url, json={"amount_minor": 5}, headers=kit.headers(tctx=tctx))
    assert response.status_code == status
    if status == 200:
        assert seen == {"account_id": "acct-1", "order": 42, "currency": "USD"}
    else:
        assert response.json()["reason_code"] == "TRANSACTION_CONTEXT_MISMATCH"


async def test_invalid_path_param_is_422_after_authentication(kit: Kit) -> None:
    pytrat = kit.pytrat()
    app = debit_app(kit, pytrat, {})
    async with serve(app, pytrat) as client:
        response = await client.post(
            "/internal/accounts/acct-1/orders/forty-two?currency=USD",
            json={"amount_minor": 5},
            headers=kit.headers(tctx=DEBIT_TCTX),
        )
    assert response.status_code == 422
    assert response.json()["reason_code"] == "REQUEST_MALFORMED"
    assert response.json()["transaction_id"]
    [event] = kit.sink.events
    assert event.reason_code is ReasonCode.TRANSACTION_CONTEXT_MISMATCH


async def test_malformed_body_without_a_token_is_401_not_422(kit: Kit) -> None:
    pytrat = kit.pytrat()
    app, _ = ledger_app(pytrat)
    async with serve(app, pytrat) as client:
        response = await client.post(
            "/internal/transfer", json={"amount_minor": "x"}, headers=kit.headers("")
        )
    assert response.status_code == 401
    assert response.json()["reason_code"] == "TOKEN_MISSING"


async def test_name_collision_between_path_and_body_is_refused_at_startup(kit: Kit) -> None:
    class Payment(BaseModel):
        currency: str

    pytrat = kit.pytrat()
    app = FastAPI()
    dependency = pytrat.require_transaction(scope="payments.transfer", bind_fields=["currency"])

    @app.post("/internal/pay/{currency}")
    async def pay(
        currency: str, body: Payment, txn: Annotated[Transaction, Depends(dependency)]
    ) -> None: ...

    with pytest.raises(ConfigurationError, match="more than one of"):
        pytrat.prepare(app)


async def test_bound_field_that_is_not_a_parameter_is_refused_at_startup(kit: Kit) -> None:
    pytrat = kit.pytrat()
    app, _ = ledger_app(pytrat, bind_fields=["amount_minr"])
    with pytest.raises(ConfigurationError, match="amount_minr"):
        pytrat.prepare(app)


async def test_non_model_body_cannot_be_bound(kit: Kit) -> None:
    pytrat = kit.pytrat()
    app = FastAPI()
    dependency = pytrat.require_transaction(scope="payments.transfer", bind_fields=["amount"])

    @app.post("/internal/raw")
    async def raw(body: dict[str, int], txn: Annotated[Transaction, Depends(dependency)]) -> None:
        raise AssertionError("must not run")

    with pytest.raises(ConfigurationError, match="amount"):
        pytrat.prepare(app)


async def test_embedded_body_binds_under_parameter_names_and_nested_paths(kit: Kit) -> None:
    pytrat = kit.pytrat()
    app = FastAPI()
    pytrat.install(app)
    dependency = pytrat.require_transaction(
        scope="payments.transfer",
        bind_fields={"transfer.amount_minor": "amount_minor", "note": "note"},
    )
    seen: dict[str, object] = {}

    @app.post("/internal/embedded")
    async def embedded(
        transfer: Transfer,
        note: Annotated[str, Body()],
        txn: Annotated[Transaction, Depends(dependency)],
    ) -> None:
        seen["amount"] = transfer.amount_minor

    async with serve(app, pytrat) as client:
        ok = await client.post(
            "/internal/embedded",
            json={"transfer": BODY, "note": "rent"},
            headers=kit.headers(tctx={"amount_minor": 10000, "note": "rent"}),
        )
        tampered = await client.post(
            "/internal/embedded",
            json={"transfer": {**BODY, "amount_minor": 1}, "note": "rent"},
            headers=kit.headers(tctx={"amount_minor": 10000, "note": "rent"}),
        )
    assert ok.status_code == 200
    assert seen == {"amount": 10000}
    assert tampered.status_code == 403


async def test_derived_binding_transforms_the_validated_value(kit: Kit) -> None:
    pytrat = kit.pytrat()
    derived = Derived("currency", "currency", lambda value: str(value).upper(), "upper")
    app, _ = ledger_app(
        pytrat, bind_fields=["source_account", "destination_account", "amount_minor", derived]
    )
    async with serve(app, pytrat) as client:
        response = await client.post(
            "/internal/transfer", json={**BODY, "currency": "usd"}, headers=kit.headers()
        )
    assert response.status_code == 200
    assert kit.sink.events[0].detail["transforms"] == "upper"


async def test_non_json_body_is_rejected(kit: Kit) -> None:
    pytrat = kit.pytrat()
    app, seen = ledger_app(pytrat)
    async with serve(app, pytrat) as client:
        response = await client.post(
            "/internal/transfer",
            content=b"amount_minor=10000",
            headers=[*kit.headers(), ("content-type", "text/plain")],
        )
        empty = await client.post("/internal/transfer", headers=kit.headers())
    assert response.status_code == 422
    assert empty.status_code == 422
    assert not seen


async def test_unbound_route_skips_request_data(kit: Kit) -> None:
    pytrat = kit.pytrat()
    app = FastAPI()
    pytrat.install(app)
    dependency = pytrat.require_transaction(scope="payments.transfer")

    @app.get("/internal/balance/{account}")
    async def balance(account: int, txn: Annotated[Transaction, Depends(dependency)]) -> dict:
        return {"txn": txn.id}

    async with serve(app, pytrat) as client:
        response = await client.get("/internal/balance/7", headers=kit.headers(txn="t-1"))
    assert response.json() == {"txn": "t-1"}


async def test_included_router_with_prefix_and_router_level_dependency(kit: Kit) -> None:
    pytrat = kit.pytrat()
    app = FastAPI()
    pytrat.install(app)
    router = APIRouter(
        dependencies=[
            Depends(pytrat.require_transaction(scope="payments.transfer", bind_fields=["item"]))
        ]
    )

    @router.get("/items/{item}")
    async def item(item: str) -> dict[str, str]:
        return {"item": item}

    app.include_router(router, prefix="/internal/v1")
    app.include_router(router, prefix="/internal/v2")
    async with serve(app, pytrat) as client:
        v1 = await client.get("/internal/v1/items/a", headers=kit.headers(tctx={"item": "a"}))
        v2 = await client.get("/internal/v2/items/b", headers=kit.headers(tctx={"item": "a"}))
    assert v1.status_code == 200
    assert v2.status_code == 403
    assert {event.policy_id for event in kit.sink.events} == {
        "GET /internal/v1/items/{item}",
        "GET /internal/v2/items/{item}",
    }


async def test_unprepared_route_fails_closed(kit: Kit) -> None:
    pytrat = kit.pytrat()
    app, seen = ledger_app(pytrat)
    import httpx

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://ledger"
    ) as client:
        response = await client.post("/internal/transfer", json=BODY, headers=kit.headers())
    assert response.status_code == 500
    assert response.json()["reason_code"] == ReasonCode.POLICY_INVALID
    assert not seen
