"""HTTP clients that propagate the bound Transaction Token to trusted destinations only.

txn-tokens-11 §12.1: the token travels in the ``Txn-Token`` header, never ``Authorization``.
CLAUDE.md invariant 7: it is never sent to a host outside the allowlist and redirects are never
followed with it. Workload authentication to the destination is separate (``auth``), because a
Transaction Token is not authentication (invariant 8).
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Awaitable, Callable, Generator, Iterable, Mapping
from types import TracebackType
from typing import Self, TypedDict, Unpack

import httpx

from pytrat.client._transport import Origin, origin_of, parse_trusted_origin
from pytrat.client.context import current_transaction, optional_transaction
from pytrat.core.constants import TXN_TOKEN_HEADER
from pytrat.core.errors import AuthorizationError, ConfigurationError, ReasonCode
from pytrat.core.validation import VerifiedToken

__all__ = [
    "AsyncReplacer",
    "AsyncTransactionClient",
    "Replacer",
    "RequestOptions",
    "TransactionClient",
]

type Replacer = Callable[[VerifiedToken], VerifiedToken]
"""Hook that exchanges the current token for a replacement before each call."""

type AsyncReplacer = Callable[[VerifiedToken], Awaitable[VerifiedToken]]
"""Async variant of :data:`Replacer`."""

_AUTHORIZATION = "authorization"


class RequestOptions(TypedDict, total=False):
    """Per-call options accepted by every request method.

    ``require_transaction=False`` permits a call when no transaction is bound; the token is still
    attached if one is.
    """

    params: Mapping[str, str] | None
    headers: Mapping[str, str] | None
    content: bytes | str | None
    data: Mapping[str, str] | None
    json: object
    timeout: float | None
    require_transaction: bool


class _Propagation:
    """Destination allowlist and header rules shared by the sync and async clients."""

    __slots__ = ("_auth", "_timeout", "_trusted")

    def __init__(
        self,
        trusted_destinations: Iterable[str],
        auth: httpx.Auth | None,
        timeout: float,
        allow_insecure_localhost: bool,
    ) -> None:
        if isinstance(trusted_destinations, str):
            raise ConfigurationError("trusted_destinations must be a collection of origins")
        self._trusted: frozenset[Origin] = frozenset(
            parse_trusted_origin(raw, allow_insecure_localhost=allow_insecure_localhost)
            for raw in trusted_destinations
        )
        if not self._trusted:
            raise ConfigurationError("trusted_destinations must not be empty")
        if timeout <= 0:
            raise ConfigurationError("timeout must be positive")
        self._auth = _GuardedAuth(auth, self) if auth is not None else None
        self._timeout = timeout

    @property
    def trusted_destinations(self) -> frozenset[str]:
        """The normalised allowlist, as ``scheme://host:port`` strings."""
        return frozenset(str(origin) for origin in self._trusted)

    @staticmethod
    def _reject_caller_txn_header(headers: Mapping[str, str] | httpx.Headers | None) -> None:
        if headers is None:
            return
        if any(name.lower() == TXN_TOKEN_HEADER.lower() for name in headers):
            # Only the bound token is ever sent; a second source would make it ambiguous which
            # transaction the call belongs to (txn-tokens-11 §12.1: exactly one token).
            raise ConfigurationError(
                "callers must not set the Txn-Token header; bind a transaction instead",
                ReasonCode.TOKEN_MALFORMED,
            )

    @staticmethod
    def _token(require_transaction: bool) -> VerifiedToken | None:
        return current_transaction() if require_transaction else optional_transaction()

    def _build(
        self,
        client: httpx.Client | httpx.AsyncClient,
        method: str,
        url: str | httpx.URL,
        options: RequestOptions,
    ) -> httpx.Request:
        headers = options.get("headers")
        self._reject_caller_txn_header(headers)
        timeout = options.get("timeout")
        try:
            request = client.build_request(
                method,
                url,
                params=options.get("params"),
                headers=headers,
                content=options.get("content"),
                data=options.get("data"),
                json=options.get("json"),
                timeout=self._timeout if timeout is None else timeout,
            )
        except httpx.InvalidURL:
            raise AuthorizationError(
                ReasonCode.DESTINATION_NOT_TRUSTED, "destination URL is invalid"
            ) from None
        self._check_destination(request.url)
        # Client-level default headers are merged by build_request; check the final set too.
        self._reject_caller_txn_header(request.headers)
        return request

    def _check_destination(self, url: httpx.URL) -> None:
        # CLAUDE.md invariant 7: exact origin match, checked before any connection is made.
        origin = origin_of(url)
        if origin is None or url.userinfo or origin not in self._trusted:
            raise AuthorizationError(
                ReasonCode.DESTINATION_NOT_TRUSTED, "destination is not in trusted_destinations"
            )

    @classmethod
    def _attach(cls, request: httpx.Request, token: VerifiedToken | None) -> None:
        if token is None:
            return
        if not isinstance(token, VerifiedToken):
            raise TypeError("replacer must return a VerifiedToken")
        request.headers[TXN_TOKEN_HEADER] = token.forwardable.reveal()
        cls._check_authorization(request)

    @staticmethod
    def _check_authorization(request: httpx.Request) -> None:
        raw = request.headers.get(TXN_TOKEN_HEADER)
        # txn-tokens-11 §12.1: Authorization MUST NOT carry the Txn-Token.
        if raw and raw in request.headers.get(_AUTHORIZATION, ""):
            raise ConfigurationError(
                "the Transaction Token must never be sent in Authorization",
                ReasonCode.TOKEN_MALFORMED,
            )

    def _check_outgoing(self, request: httpx.Request) -> None:
        """Re-check a request produced by an auth flow, immediately before it is sent."""
        self._check_destination(request.url)
        self._check_authorization(request)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(trusted_destinations={sorted(self.trusted_destinations)})"


class _GuardedAuth(httpx.Auth):
    """Wraps caller-supplied auth so every request it yields is re-checked before sending.

    An auth flow runs after the Txn-Token is attached and may add headers or issue extra
    requests; none of them may copy the token into ``Authorization`` or leave the allowlist.
    """

    def __init__(self, inner: httpx.Auth, guard: _Propagation) -> None:
        self._inner = inner
        self._guard = guard

    def sync_auth_flow(
        self, request: httpx.Request
    ) -> Generator[httpx.Request, httpx.Response, None]:
        flow = self._inner.sync_auth_flow(request)
        outgoing = next(flow)
        while True:
            self._guard._check_outgoing(outgoing)
            response = yield outgoing
            try:
                outgoing = flow.send(response)
            except StopIteration:
                return

    async def async_auth_flow(
        self, request: httpx.Request
    ) -> AsyncGenerator[httpx.Request, httpx.Response]:
        flow = self._inner.async_auth_flow(request)
        outgoing = await anext(flow)
        while True:
            self._guard._check_outgoing(outgoing)
            response = yield outgoing
            try:
                outgoing = await flow.asend(response)
            except StopAsyncIteration:
                return


class TransactionClient(_Propagation):
    """Synchronous HTTP client that adds the bound ``Txn-Token`` to trusted destinations.

    Args:
        trusted_destinations: Exact ``scheme://host[:port]`` origins the token may be sent to.
        http_client: Optional ``httpx.Client`` to use; closed only if this instance created it.
        auth: Optional ``httpx.Auth`` authenticating this workload to the destination.
        replacer: Optional hook called before each call to obtain a replacement token.
        timeout: Default per-request timeout in seconds.
        allow_insecure_localhost: Permit ``http://`` origins on localhost only.

    Raises:
        ConfigurationError: If the allowlist is empty or contains an invalid or non-HTTPS origin.
    """

    __slots__ = ("_http", "_owns_http", "_replacer")

    def __init__(
        self,
        trusted_destinations: Iterable[str],
        *,
        http_client: httpx.Client | None = None,
        auth: httpx.Auth | None = None,
        replacer: Replacer | None = None,
        timeout: float = 10.0,
        allow_insecure_localhost: bool = False,
    ) -> None:
        super().__init__(trusted_destinations, auth, timeout, allow_insecure_localhost)
        self._replacer = replacer
        self._owns_http = http_client is None
        self._http = http_client or httpx.Client(timeout=timeout, follow_redirects=False)

    def request(
        self,
        method: str,
        url: str | httpx.URL,
        **options: Unpack[RequestOptions],
    ) -> httpx.Response:
        """Send a request carrying the bound Transaction Token.

        Redirect responses are returned to the caller, never followed.

        Raises:
            AuthorizationError: ``DESTINATION_NOT_TRUSTED`` before connecting to an unlisted origin.
            TokenError: ``TOKEN_MISSING`` if no transaction is bound and ``require_transaction``.
            ConfigurationError: If the caller supplies a ``Txn-Token`` header.
        """
        token = self._token(options.get("require_transaction", True))
        request = self._build(self._http, method, url, options)
        if token is not None and self._replacer is not None:
            token = self._replacer(token)
        self._attach(request, token)
        if self._auth is None:
            return self._http.send(request, follow_redirects=False)
        return self._http.send(request, auth=self._auth, follow_redirects=False)

    def get(self, url: str | httpx.URL, **options: Unpack[RequestOptions]) -> httpx.Response:
        """Send a GET request; see :meth:`request`."""
        return self.request("GET", url, **options)

    def post(self, url: str | httpx.URL, **options: Unpack[RequestOptions]) -> httpx.Response:
        """Send a POST request; see :meth:`request`."""
        return self.request("POST", url, **options)

    def put(self, url: str | httpx.URL, **options: Unpack[RequestOptions]) -> httpx.Response:
        """Send a PUT request; see :meth:`request`."""
        return self.request("PUT", url, **options)

    def patch(self, url: str | httpx.URL, **options: Unpack[RequestOptions]) -> httpx.Response:
        """Send a PATCH request; see :meth:`request`."""
        return self.request("PATCH", url, **options)

    def delete(self, url: str | httpx.URL, **options: Unpack[RequestOptions]) -> httpx.Response:
        """Send a DELETE request; see :meth:`request`."""
        return self.request("DELETE", url, **options)

    def close(self) -> None:
        """Close the underlying HTTP client if this instance created it."""
        if self._owns_http:
            self._http.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


class AsyncTransactionClient(_Propagation):
    """Asynchronous variant of :class:`TransactionClient`."""

    __slots__ = ("_http", "_owns_http", "_replacer")

    def __init__(
        self,
        trusted_destinations: Iterable[str],
        *,
        http_client: httpx.AsyncClient | None = None,
        auth: httpx.Auth | None = None,
        replacer: AsyncReplacer | None = None,
        timeout: float = 10.0,
        allow_insecure_localhost: bool = False,
    ) -> None:
        super().__init__(trusted_destinations, auth, timeout, allow_insecure_localhost)
        self._replacer = replacer
        self._owns_http = http_client is None
        self._http = http_client or httpx.AsyncClient(timeout=timeout, follow_redirects=False)

    async def request(
        self,
        method: str,
        url: str | httpx.URL,
        **options: Unpack[RequestOptions],
    ) -> httpx.Response:
        """Async variant of :meth:`TransactionClient.request`."""
        token = self._token(options.get("require_transaction", True))
        request = self._build(self._http, method, url, options)
        if token is not None and self._replacer is not None:
            token = await self._replacer(token)
        self._attach(request, token)
        if self._auth is None:
            return await self._http.send(request, follow_redirects=False)
        return await self._http.send(request, auth=self._auth, follow_redirects=False)

    async def get(self, url: str | httpx.URL, **options: Unpack[RequestOptions]) -> httpx.Response:
        """Send a GET request; see :meth:`request`."""
        return await self.request("GET", url, **options)

    async def post(self, url: str | httpx.URL, **options: Unpack[RequestOptions]) -> httpx.Response:
        """Send a POST request; see :meth:`request`."""
        return await self.request("POST", url, **options)

    async def put(self, url: str | httpx.URL, **options: Unpack[RequestOptions]) -> httpx.Response:
        """Send a PUT request; see :meth:`request`."""
        return await self.request("PUT", url, **options)

    async def patch(
        self, url: str | httpx.URL, **options: Unpack[RequestOptions]
    ) -> httpx.Response:
        """Send a PATCH request; see :meth:`request`."""
        return await self.request("PATCH", url, **options)

    async def delete(
        self, url: str | httpx.URL, **options: Unpack[RequestOptions]
    ) -> httpx.Response:
        """Send a DELETE request; see :meth:`request`."""
        return await self.request("DELETE", url, **options)

    async def aclose(self) -> None:
        """Close the underlying HTTP client if this instance created it."""
        if self._owns_http:
            await self._http.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()
