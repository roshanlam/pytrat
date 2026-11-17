import time
from pathlib import Path

import httpx
from first_route import create_app

from pytrat.client import WorkloadJwtAuth
from pytrat.core import TXN_TOKEN_HEADER, FrozenClock, WorkloadKeys
from pytrat.core.crypto import private_key_to_pem
from pytrat.core.testing import TokenFactory, generate_test_key

LEDGER = "https://ledger.internal"
TRANSFER = {
    "source_account": "account-A",
    "destination_account": "account-B",
    "amount_minor": 10000,
    "currency": "USD",
}


async def test_ledger_records_only_the_authorized_transfer(tmp_path: Path) -> None:
    # Test-only stand-in for the TTS: mints tokens whose tctx authorizes TRANSFER.
    tts = TokenFactory.create("ES256", clock=FrozenClock(time.time()))
    caller = generate_test_key("ES256", kid="payment-service")
    caller_pem = tmp_path / "payment-service.pem"
    caller_pem.write_bytes(private_key_to_pem(caller.private_key))

    app = create_app(tts.key.key_set(), WorkloadKeys({"payment-service": caller.key_set()}))
    # Signs a fresh workload JWT for each request, addressed to the ledger.
    as_payment_service = WorkloadJwtAuth(
        workload_id="payment-service",
        private_key_path=caller_pem,
        kid="payment-service",
        alg="ES256",
        audiences={LEDGER: "ledger-service"},
    )
    url = "/internal/ledger/entries"
    transport = httpx.ASGITransport(app=app)

    async with (
        app.router.lifespan_context(app),  # runs PyTraT's startup checks
        httpx.AsyncClient(transport=transport, base_url=LEDGER) as client,
    ):
        token = {TXN_TOKEN_HEADER: tts.mint()}

        honest = await client.post(url, json=TRANSFER, headers=token, auth=as_payment_service)
        assert honest.status_code == 201

        tampered = {**TRANSFER, "amount_minor": 900_000}
        denied = await client.post(url, json=tampered, headers=token, auth=as_payment_service)
        assert denied.status_code == 403
        assert denied.json()["reason_code"] == "TRANSACTION_CONTEXT_MISMATCH"

        no_token = await client.post(url, json=TRANSFER, auth=as_payment_service)
        assert no_token.status_code == 401
        assert no_token.json()["reason_code"] == "TOKEN_MISSING"

        no_caller = await client.post(url, json=TRANSFER, headers=token)
        assert no_caller.status_code == 401
        assert no_caller.json()["reason_code"] == "WORKLOAD_UNAUTHENTICATED"
