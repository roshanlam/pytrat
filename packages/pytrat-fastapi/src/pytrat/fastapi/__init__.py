"""PyTraT for FastAPI: Transaction Token enforcement as a dependency.

::

    pytrat = PyTraT(service="ledger-service", verifier=verifier, authenticator=authn,
                    audit=sink, protected_prefixes=("/internal",))
    app = FastAPI(lifespan=pytrat.lifespan)
    pytrat.install(app)

    @app.post("/internal/transfer")
    async def transfer(
        body: Transfer,
        txn: Annotated[Transaction, Depends(pytrat.require_transaction(
            scope="payments.transfer", bind_fields=["amount_minor", "currency"]))],
    ): ...
"""

from pytrat.fastapi.dependencies import TransactionDependency, inbound_request
from pytrat.fastapi.edge import SubjectTokenExtractor, bearer_token, initiate_transaction
from pytrat.fastapi.integration import PyTraT
from pytrat.fastapi.middleware import TransactionMiddleware
from pytrat.fastapi.responses import (
    PROBLEM_CONTENT_TYPE,
    MalformedRequestError,
    exception_handler,
    problem_body,
    problem_response,
)
from pytrat.fastapi.settings import PyTraTSettings
from pytrat.policy import Transaction

__all__ = [
    "PROBLEM_CONTENT_TYPE",
    "MalformedRequestError",
    "PyTraT",
    "PyTraTSettings",
    "SubjectTokenExtractor",
    "Transaction",
    "TransactionDependency",
    "TransactionMiddleware",
    "bearer_token",
    "exception_handler",
    "inbound_request",
    "initiate_transaction",
    "problem_body",
    "problem_response",
]
