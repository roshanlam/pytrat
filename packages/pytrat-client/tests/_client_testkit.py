"""Shared helpers and fixtures for pytrat-client tests.

Behavioural tests are written once against small adapters with an ``async`` interface; the sync
adapter calls the synchronous shell directly, so every test runs against both shells.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field

import httpx
import pytest

from pytrat.client import (
    AsyncJwksRefresher,
    AsyncTransactionClient,
    AsyncTransactionTokenClient,
    ExchangeRequest,
    JwksRefresher,
    TransactionClient,
    TransactionTokenClient,
    verify_with_refresh,
    verify_with_refresh_async,
)
from pytrat.core import TokenVerifier, VerifiedToken
from pytrat.core.constants import TOKEN_TYPE_TXN_TOKEN
from pytrat.core.testing import FrozenClock, TokenFactory

TOKEN_ENDPOINT = "https://tts.internal/token"
JWKS_URL = "https://tts.internal/.well-known/jwks.json"

type Handler = Callable[[httpx.Request], httpx.Response]


@dataclass
class Recorder:
    """A MockTransport handler that records every request it receives."""

    respond: Handler
    requests: list[httpx.Request] = field(default_factory=list)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.respond(request)

    @property
    def calls(self) -> int:
        return len(self.requests)


def tts_success(access_token: str, **overrides: object) -> httpx.Response:
    body: dict[str, object] = {
        "access_token": access_token,
        "issued_token_type": TOKEN_TYPE_TXN_TOKEN,
        "token_type": "N_A",
        **overrides,
    }
    body = {k: v for k, v in body.items() if v is not None}
    return httpx.Response(200, json=body)


def tts_error(status: int, error: object, description: object = None) -> httpx.Response:
    body: dict[str, object] = {"error": error}
    if description is not None:
        body["error_description"] = description
    return httpx.Response(
        status, content=json.dumps(body).encode(), headers={"content-type": "application/json"}
    )


class StaticCredential:
    """Minimal WorkloadCredential for shell tests."""

    def apply(self, request: ExchangeRequest) -> ExchangeRequest:
        return request.with_form({"client_id": "gateway"})


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock()


@pytest.fixture
def factory(clock: FrozenClock) -> TokenFactory:
    return TokenFactory.create(clock=clock)


@pytest.fixture
def verifier(factory: TokenFactory) -> TokenVerifier:
    return factory.verifier()


@pytest.fixture
def current(factory: TokenFactory, verifier: TokenVerifier) -> VerifiedToken:
    return verifier.verify(factory.mint(scope="payments.read payments.transfer"))


class SyncTokenShell:
    def __init__(self, handler: Handler, verifier: TokenVerifier, **kwargs: object) -> None:
        credential = kwargs.pop("credential", StaticCredential())
        self.client = TransactionTokenClient(
            str(kwargs.pop("endpoint", TOKEN_ENDPOINT)),
            credential,  # type: ignore[arg-type]
            verifier,
            http_client=httpx.Client(transport=httpx.MockTransport(handler)),
            **kwargs,  # type: ignore[arg-type]
        )

    async def issue(self, **kwargs: object) -> VerifiedToken:
        return self.client.issue(**kwargs)  # type: ignore[arg-type]

    async def replace(self, current: VerifiedToken, **kwargs: object) -> VerifiedToken:
        return self.client.replace(current, **kwargs)  # type: ignore[arg-type]


class AsyncTokenShell:
    def __init__(self, handler: Handler, verifier: TokenVerifier, **kwargs: object) -> None:
        credential = kwargs.pop("credential", StaticCredential())
        self.client = AsyncTransactionTokenClient(
            str(kwargs.pop("endpoint", TOKEN_ENDPOINT)),
            credential,  # type: ignore[arg-type]
            verifier,
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
            **kwargs,  # type: ignore[arg-type]
        )

    async def issue(self, **kwargs: object) -> VerifiedToken:
        return await self.client.issue(**kwargs)  # type: ignore[arg-type]

    async def replace(self, current: VerifiedToken, **kwargs: object) -> VerifiedToken:
        return await self.client.replace(current, **kwargs)  # type: ignore[arg-type]


@pytest.fixture(params=["sync", "async"])
def token_shell(request: pytest.FixtureRequest) -> type[SyncTokenShell] | type[AsyncTokenShell]:
    return SyncTokenShell if request.param == "sync" else AsyncTokenShell


class SyncHttpShell:
    def __init__(self, handler: Handler, trusted: list[str], **kwargs: object) -> None:
        http_client = kwargs.pop("http_client", None) or httpx.Client(
            transport=httpx.MockTransport(handler)
        )
        self.client = TransactionClient(trusted, http_client=http_client, **kwargs)  # type: ignore[arg-type]

    async def request(self, method: str, url: str, **kwargs: object) -> httpx.Response:
        return self.client.request(method, url, **kwargs)  # type: ignore[arg-type]

    async def verb(self, name: str, url: str, **kwargs: object) -> httpx.Response:
        return getattr(self.client, name)(url, **kwargs)  # type: ignore[no-any-return]


class AsyncHttpShell:
    def __init__(self, handler: Handler, trusted: list[str], **kwargs: object) -> None:
        replacer = kwargs.pop("replacer", None)
        if replacer is not None:
            sync_replacer = replacer

            async def async_replacer(token: VerifiedToken) -> VerifiedToken:
                return sync_replacer(token)  # type: ignore[operator,no-any-return]

            kwargs["replacer"] = async_replacer
        http_client = kwargs.pop("http_client", None) or httpx.AsyncClient(
            transport=httpx.MockTransport(handler)
        )
        if isinstance(http_client, httpx.Client):
            raise TypeError("pass an AsyncClient")
        self.client = AsyncTransactionClient(trusted, http_client=http_client, **kwargs)  # type: ignore[arg-type]

    async def request(self, method: str, url: str, **kwargs: object) -> httpx.Response:
        return await self.client.request(method, url, **kwargs)  # type: ignore[arg-type]

    async def verb(self, name: str, url: str, **kwargs: object) -> httpx.Response:
        return await getattr(self.client, name)(url, **kwargs)  # type: ignore[no-any-return]


@pytest.fixture(params=["sync", "async"])
def http_shell(request: pytest.FixtureRequest) -> type[SyncHttpShell] | type[AsyncHttpShell]:
    return SyncHttpShell if request.param == "sync" else AsyncHttpShell


class SyncJwksShell:
    def __init__(self, handler: Handler, clock: FrozenClock, **kwargs: object) -> None:
        self.refresher = JwksRefresher(
            JWKS_URL,
            clock=clock,
            http_client=httpx.Client(transport=httpx.MockTransport(handler)),
            **kwargs,  # type: ignore[arg-type]
        )

    async def refresh(self, *, force: bool = False) -> bool:
        return self.refresher.refresh(force=force)

    async def verify(self, verifier: TokenVerifier, raw: str) -> VerifiedToken:
        return verify_with_refresh(verifier, self.refresher, raw)


class AsyncJwksShell:
    def __init__(self, handler: Handler, clock: FrozenClock, **kwargs: object) -> None:
        self.refresher = AsyncJwksRefresher(
            JWKS_URL,
            clock=clock,
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
            **kwargs,  # type: ignore[arg-type]
        )

    async def refresh(self, *, force: bool = False) -> bool:
        return await self.refresher.refresh(force=force)

    async def verify(self, verifier: TokenVerifier, raw: str) -> VerifiedToken:
        return await verify_with_refresh_async(verifier, self.refresher, raw)


@pytest.fixture(params=["sync", "async"])
def jwks_shell(request: pytest.FixtureRequest) -> type[SyncJwksShell] | type[AsyncJwksShell]:
    return SyncJwksShell if request.param == "sync" else AsyncJwksShell
