import httpx
import pytest
from first_route import TRUST_DOMAIN, create_app

from pytrat.core.testing.pytest_plugin import TransactionTestKit

TRANSFER = {
    "source_account": "account-A",
    "destination_account": "account-B",
    "amount_minor": 10000,
    "currency": "USD",
}


@pytest.fixture
def pytrat_trust_domain() -> str:
    return TRUST_DOMAIN  # pytrat_kit mints tokens for this Trust Domain


async def test_ledger_records_only_the_authorized_transfer(pytrat_kit: TransactionTestKit) -> None:
    # pytrat_kit stands in for the TTS and for the payment service; its keys live in memory.
    app = create_app(pytrat_kit.tts_keys(), pytrat_kit.workload_keys("payment-service"))
    authorized = pytrat_kit.headers(
        scope="payments.transfer",
        tctx=TRANSFER,
        caller="payment-service",
        audience="ledger-service",
    )
    url = "/internal/ledger/entries"
    transport = httpx.ASGITransport(app=app)

    async with (
        app.router.lifespan_context(app),  # runs PyTraT's startup checks
        httpx.AsyncClient(transport=transport, base_url="https://ledger.internal") as client,
    ):
        honest = await client.post(url, json=TRANSFER, headers=authorized)
        assert honest.status_code == 201

        tampered = {**TRANSFER, "amount_minor": 900_000}
        denied = await client.post(url, json=tampered, headers=authorized)
        assert denied.status_code == 403
        assert denied.json()["reason_code"] == "TRANSACTION_CONTEXT_MISMATCH"

        no_caller = pytrat_kit.headers(scope="payments.transfer", tctx=TRANSFER)
        unauthenticated = await client.post(url, json=TRANSFER, headers=no_caller)
        assert unauthenticated.status_code == 401
        assert unauthenticated.json()["reason_code"] == "WORKLOAD_UNAUTHENTICATED"
