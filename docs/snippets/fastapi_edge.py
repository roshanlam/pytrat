from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from pytrat.client import AsyncTransactionClient, AsyncTransactionTokenClient
from pytrat.core import PyTraTError
from pytrat.fastapi import exception_handler, initiate_transaction

PAYMENTS = "https://payment.payments.internal"


class Transfer(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    source_account: str
    destination_account: str
    amount_minor: int
    currency: str


def create_gateway(tts: AsyncTransactionTokenClient, payments: AsyncTransactionClient) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        async with tts, payments:  # close both HTTP clients on shutdown
            yield

    app = FastAPI(lifespan=lifespan)
    app.add_exception_handler(PyTraTError, exception_handler())  # RFC 9457 problem responses

    @app.post("/transfers")
    async def create_transfer(transfer: Transfer, request: Request) -> JSONResponse:
        # Exchange the caller's bearer access token for a Txn-Token whose tctx is exactly the
        # validated transfer, and bind it for the block: outbound calls carry it automatically.
        async with initiate_transaction(
            request,
            client=tts,
            audience="payments.internal",
            scope="payments.transfer",
            request_details=transfer.model_dump(),
            request_context={"channel": "web"},
        ) as txn:
            response = await payments.post(
                f"{PAYMENTS}/internal/payments", json=transfer.model_dump()
            )
        return JSONResponse(
            {"transaction_id": txn.id, "payment_status": response.status_code},
            status_code=response.status_code,
        )

    return app
