"""Transaction initiation at the trusted edge (txn-tokens-11 §11).

The edge (an API gateway or the first internal service) exchanges the caller's access token for a
Transaction Token and binds it for the outbound calls it makes on the caller's behalf. The access
token is wrapped in a :class:`~pytrat.core.SecretToken` from the moment it is read, so it never
reaches a log, an exception message or a response.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager

from starlette.requests import Request

from pytrat.client.context import bind_transaction
from pytrat.client.token_client import AsyncTransactionTokenClient
from pytrat.core.constants import TOKEN_TYPE_ACCESS_TOKEN
from pytrat.core.errors import AuthenticationError, ReasonCode
from pytrat.core.scopes import Scope
from pytrat.core.secret import SecretToken
from pytrat.core.validation import VerifiedToken

__all__ = ["SubjectTokenExtractor", "bearer_token", "initiate_transaction"]

type SubjectTokenExtractor = Callable[[Request], SecretToken]
"""Reads the subject token from the incoming request or raises ``SUBJECT_TOKEN_INVALID``."""

_BEARER = "bearer"


def _invalid(detail: str) -> AuthenticationError:
    return AuthenticationError(ReasonCode.SUBJECT_TOKEN_INVALID, detail)


def bearer_token(request: Request) -> SecretToken:
    """Extract an RFC 6750 bearer token from exactly one ``Authorization`` header.

    Raises:
        AuthenticationError: ``SUBJECT_TOKEN_INVALID`` (HTTP 401, ``WWW-Authenticate: Bearer``)
            if the header is absent, repeated, not a bearer credential, or empty.
    """
    values = request.headers.getlist("authorization")
    if len(values) != 1:
        raise _invalid("exactly one Authorization header is required")
    scheme, _, credentials = values[0].strip().partition(" ")
    credentials = credentials.strip()
    if scheme.lower() != _BEARER or not credentials or " " in credentials:
        raise _invalid("Authorization header is not a bearer credential")
    return SecretToken(credentials)


@asynccontextmanager
async def initiate_transaction(
    request: Request,
    *,
    client: AsyncTransactionTokenClient,
    audience: str,
    scope: Scope | str,
    request_details: Mapping[str, object] | None = None,
    request_context: Mapping[str, object] | None = None,
    subject_token_type: str = TOKEN_TYPE_ACCESS_TOKEN,
    extract_subject_token: SubjectTokenExtractor = bearer_token,
) -> AsyncIterator[VerifiedToken]:
    """Obtain a Transaction Token for ``request`` and bind it for the ``async with`` block.

    Use it in the edge handler, after the body has been validated, so ``request_details`` (which
    the TTS turns into ``tctx``) is exactly what the handler will act on::

        async with initiate_transaction(request, client=tts, audience="payments.internal",
                                        scope="payments.transfer",
                                        request_details=body.model_dump()) as txn:
            await payments.post("https://payments.internal/transfer", json=body.model_dump())

    Args:
        request: The incoming request.
        client: Client for the Transaction Token Service; it verifies the issued token.
        audience: The Trust Domain.
        scope: Requested scope.
        request_details: Becomes the token's ``tctx`` (subject to TTS policy).
        request_context: Becomes the token's ``rctx``.
        subject_token_type: Type URI of the subject token.
        extract_subject_token: Reads the subject token; defaults to :func:`bearer_token`.

    Yields:
        The verified Transaction Token, bound as the current transaction.

    Raises:
        AuthenticationError: ``SUBJECT_TOKEN_INVALID`` if no usable subject token is presented.
        ExchangeError, TokenError, DependencyError: From the token exchange.
    """
    subject_token = extract_subject_token(request)
    token = await client.issue(
        audience=audience,
        scope=scope,
        subject_token=subject_token,
        subject_token_type=subject_token_type,
        request_context=request_context,
        request_details=request_details,
    )
    with bind_transaction(token):
        yield token
