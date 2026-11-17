"""Sync and async Transaction Token Service clients: thin I/O shells over :mod:`exchange`."""

from __future__ import annotations

import logging
import ssl
from collections.abc import Mapping
from dataclasses import dataclass
from types import TracebackType
from typing import Self

import httpx

from pytrat.client._transport import BoundedBody, require_secure_endpoint
from pytrat.client.credentials import MtlsCredential, WorkloadCredential
from pytrat.client.exchange import (
    MAX_EXCHANGE_RESPONSE_BYTES,
    ExchangeRequest,
    build_issue_request,
    build_replacement_request,
    check_replacement,
    parse_exchange_response,
    response_too_large,
)
from pytrat.core.errors import ConfigurationError, DependencyError
from pytrat.core.scopes import Scope
from pytrat.core.secret import SecretToken
from pytrat.core.validation import TokenVerifier, VerifiedToken

__all__ = ["AsyncTransactionTokenClient", "TransactionTokenClient"]

_log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class _Outgoing:
    body: bytes
    headers: Mapping[str, str]
    redact: tuple[SecretToken, ...]

    def __repr__(self) -> str:
        return "_Outgoing(...)"


class _ExchangeCore:
    """Configuration and the pure steps both shells share."""

    __slots__ = ("_credential", "_endpoint", "_timeout", "_verifier")

    def __init__(
        self,
        token_endpoint: str,
        credential: WorkloadCredential,
        verifier: TokenVerifier,
        timeout: float,
        allow_insecure_localhost: bool,
    ) -> None:
        self._endpoint = require_secure_endpoint(
            token_endpoint, allow_insecure_localhost=allow_insecure_localhost, what="token_endpoint"
        )
        if not isinstance(verifier, TokenVerifier):
            raise ConfigurationError("verifier must be a TokenVerifier")
        if timeout <= 0:
            raise ConfigurationError("timeout must be positive")
        self._credential = credential
        self._verifier = verifier
        self._timeout = timeout

    def _outgoing(self, request: ExchangeRequest) -> _Outgoing:
        prepared = self._credential.apply(request)
        redact = tuple(
            SecretToken(prepared.form[name])
            for name in ("subject_token", "client_assertion")
            if prepared.form.get(name)
        )
        return _Outgoing(body=prepared.body(), headers=prepared.headers, redact=redact)

    def _finish(
        self,
        response: httpx.Response,
        body: BoundedBody,
        outgoing: _Outgoing,
        current: VerifiedToken | None,
    ) -> VerifiedToken:
        if body.exceeded:
            raise response_too_large()
        raw_token = parse_exchange_response(
            response.status_code, response.headers, body.value(), redact=outgoing.redact
        )
        # Every token from the TTS is verified locally; the transport alone is not trusted.
        verified = self._verifier.verify(raw_token.reveal())
        if current is not None:
            check_replacement(current, verified)
        _log.debug("transaction token received txn=%s digest=%s", verified.id, verified.digest)
        return verified

    def __repr__(self) -> str:
        return f"{type(self).__name__}(token_endpoint={str(self._endpoint)!r})"


def _ssl(credential: WorkloadCredential) -> ssl.SSLContext | bool:
    # An mTLS credential authenticates in the handshake, so a self-built transport must present it.
    if isinstance(credential, MtlsCredential):
        return credential.ssl_context()
    return True


def _unreachable() -> DependencyError:
    return DependencyError("transaction token service is unreachable")


class TransactionTokenClient(_ExchangeCore):
    """Synchronous client for a Transaction Token Service token endpoint.

    Owns (and closes) its ``httpx.Client`` only if it created it. Redirects are never followed.
    """

    __slots__ = ("_http", "_owns_http")

    def __init__(
        self,
        token_endpoint: str,
        credential: WorkloadCredential,
        verifier: TokenVerifier,
        *,
        http_client: httpx.Client | None = None,
        timeout: float = 5.0,
        allow_insecure_localhost: bool = False,
    ) -> None:
        super().__init__(token_endpoint, credential, verifier, timeout, allow_insecure_localhost)
        self._owns_http = http_client is None
        self._http = http_client or httpx.Client(
            timeout=timeout, follow_redirects=False, verify=_ssl(self._credential)
        )

    def issue(
        self,
        *,
        audience: str,
        scope: Scope | str,
        subject_token: SecretToken,
        subject_token_type: str,
        request_context: Mapping[str, object] | None = None,
        request_details: Mapping[str, object] | None = None,
    ) -> VerifiedToken:
        """Request and verify a new Transaction Token (txn-tokens-11 §11).

        Raises:
            ExchangeError: If the request is refused or the response does not conform to §11.4.
            TokenError: If the issued token fails local verification.
            DependencyError: ``DEPENDENCY_UNAVAILABLE`` on network failure.
        """
        request = build_issue_request(
            audience=audience,
            scope=scope,
            subject_token=subject_token,
            subject_token_type=subject_token_type,
            request_context=request_context,
            request_details=request_details,
        )
        return self._exchange(request, None)

    def replace(
        self,
        current: VerifiedToken,
        scope: Scope | None = None,
        *,
        request_context: Mapping[str, object] | None = None,
        request_details: Mapping[str, object] | None = None,
    ) -> VerifiedToken:
        """Request and verify a replacement for ``current`` (txn-tokens-11 §13.15).

        Raises:
            AuthorizationError: ``REPLACEMENT_WIDENS_AUTHORIZATION`` if ``scope`` widens the
                current scope (before any I/O) or the TTS reply does not attenuate ``current``.
            ExchangeError, TokenError, DependencyError: As for :meth:`issue`.
        """
        request = build_replacement_request(
            current, scope=scope, request_context=request_context, request_details=request_details
        )
        return self._exchange(request, current)

    def _exchange(self, request: ExchangeRequest, current: VerifiedToken | None) -> VerifiedToken:
        outgoing = self._outgoing(request)
        body = BoundedBody(MAX_EXCHANGE_RESPONSE_BYTES)
        try:
            with self._http.stream(
                "POST",
                self._endpoint,
                content=outgoing.body,
                headers=dict(outgoing.headers),
                timeout=self._timeout,
                follow_redirects=False,
            ) as response:
                for chunk in response.iter_bytes():
                    if not body.feed(chunk):
                        break
        except httpx.HTTPError:
            raise _unreachable() from None
        return self._finish(response, body, outgoing, current)

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


class AsyncTransactionTokenClient(_ExchangeCore):
    """Asynchronous client for a Transaction Token Service token endpoint.

    Owns (and closes) its ``httpx.AsyncClient`` only if it created it. Redirects are never
    followed.
    """

    __slots__ = ("_http", "_owns_http")

    def __init__(
        self,
        token_endpoint: str,
        credential: WorkloadCredential,
        verifier: TokenVerifier,
        *,
        http_client: httpx.AsyncClient | None = None,
        timeout: float = 5.0,
        allow_insecure_localhost: bool = False,
    ) -> None:
        super().__init__(token_endpoint, credential, verifier, timeout, allow_insecure_localhost)
        self._owns_http = http_client is None
        self._http = http_client or httpx.AsyncClient(
            timeout=timeout, follow_redirects=False, verify=_ssl(self._credential)
        )

    async def issue(
        self,
        *,
        audience: str,
        scope: Scope | str,
        subject_token: SecretToken,
        subject_token_type: str,
        request_context: Mapping[str, object] | None = None,
        request_details: Mapping[str, object] | None = None,
    ) -> VerifiedToken:
        """Async variant of :meth:`TransactionTokenClient.issue`."""
        request = build_issue_request(
            audience=audience,
            scope=scope,
            subject_token=subject_token,
            subject_token_type=subject_token_type,
            request_context=request_context,
            request_details=request_details,
        )
        return await self._exchange(request, None)

    async def replace(
        self,
        current: VerifiedToken,
        scope: Scope | None = None,
        *,
        request_context: Mapping[str, object] | None = None,
        request_details: Mapping[str, object] | None = None,
    ) -> VerifiedToken:
        """Async variant of :meth:`TransactionTokenClient.replace`."""
        request = build_replacement_request(
            current, scope=scope, request_context=request_context, request_details=request_details
        )
        return await self._exchange(request, current)

    async def _exchange(
        self, request: ExchangeRequest, current: VerifiedToken | None
    ) -> VerifiedToken:
        outgoing = self._outgoing(request)
        body = BoundedBody(MAX_EXCHANGE_RESPONSE_BYTES)
        try:
            async with self._http.stream(
                "POST",
                self._endpoint,
                content=outgoing.body,
                headers=dict(outgoing.headers),
                timeout=self._timeout,
                follow_redirects=False,
            ) as response:
                async for chunk in response.aiter_bytes():
                    if not body.feed(chunk):
                        break
        except httpx.HTTPError:
            raise _unreachable() from None
        return self._finish(response, body, outgoing, current)

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
