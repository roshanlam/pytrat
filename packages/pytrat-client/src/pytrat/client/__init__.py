"""PyTraT client: RFC 8693 token exchange, workload credentials and Txn-Token propagation.

Depends only on :mod:`pytrat.core` and ``httpx``.
"""

from pytrat.client.context import bind_transaction, current_transaction, optional_transaction
from pytrat.client.credentials import (
    MtlsCredential,
    PrivateKeyJwtCredential,
    SpiffeJwtSvidCredential,
    WorkloadCredential,
)
from pytrat.client.exchange import (
    ExchangeError,
    ExchangeRequest,
    build_issue_request,
    build_replacement_request,
    check_replacement,
    parse_exchange_response,
)
from pytrat.client.http import (
    AsyncReplacer,
    AsyncTransactionClient,
    Replacer,
    RequestOptions,
    TransactionClient,
)
from pytrat.client.jwks import (
    AsyncJwksRefresher,
    JwksRefresher,
    RefreshingKeyProvider,
    parse_jwks,
    verify_with_refresh,
    verify_with_refresh_async,
)
from pytrat.client.token_client import AsyncTransactionTokenClient, TransactionTokenClient

__all__ = [
    "AsyncJwksRefresher",
    "AsyncReplacer",
    "AsyncTransactionClient",
    "AsyncTransactionTokenClient",
    "ExchangeError",
    "ExchangeRequest",
    "JwksRefresher",
    "MtlsCredential",
    "PrivateKeyJwtCredential",
    "RefreshingKeyProvider",
    "Replacer",
    "RequestOptions",
    "SpiffeJwtSvidCredential",
    "TransactionClient",
    "TransactionTokenClient",
    "WorkloadCredential",
    "bind_transaction",
    "build_issue_request",
    "build_replacement_request",
    "check_replacement",
    "current_transaction",
    "optional_transaction",
    "parse_exchange_response",
    "parse_jwks",
    "verify_with_refresh",
    "verify_with_refresh_async",
]
