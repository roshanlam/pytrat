"""Propagating HTTP clients (txn-tokens-11 §12.1), run against both shells."""

from __future__ import annotations

import httpx
import pytest

from _client_testkit import Recorder
from pytrat.client import AsyncTransactionClient, TransactionClient, bind_transaction
from pytrat.core import AuthorizationError, ConfigurationError, ReasonCode, TokenError
from pytrat.core.constants import TXN_TOKEN_HEADER

TRUSTED = ["https://ledger.internal", "https://Risk.Internal:8443"]


def ok(_: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"ok": True})


async def test_bound_token_is_sent_in_txn_token_header(http_shell, current) -> None:
    recorder = Recorder(ok)
    shell = http_shell(recorder, TRUSTED)
    with bind_transaction(current):
        response = await shell.request("POST", "https://ledger.internal/entries", json={"a": 1})
    assert response.status_code == 200
    (sent,) = recorder.requests
    assert sent.headers.get_list(TXN_TOKEN_HEADER) == [current.forwardable.reveal()]
    assert "authorization" not in sent.headers


async def test_token_never_sent_in_authorization_header(http_shell, current) -> None:
    recorder = Recorder(ok)
    shell = http_shell(recorder, TRUSTED, auth=httpx.BasicAuth("svc", "pw"))
    with bind_transaction(current):
        await shell.request("GET", "https://ledger.internal/x")
    sent = recorder.requests[0]
    assert sent.headers["authorization"].startswith("Basic ")
    assert current.forwardable.reveal() not in sent.headers["authorization"]
    assert sent.headers[TXN_TOKEN_HEADER] == current.forwardable.reveal()


async def test_caller_copying_token_into_authorization_is_refused(http_shell, current) -> None:
    recorder = Recorder(ok)
    shell = http_shell(recorder, TRUSTED)
    raw = current.forwardable.reveal()
    with bind_transaction(current), pytest.raises(ConfigurationError):
        await shell.request(
            "GET", "https://ledger.internal/x", headers={"Authorization": f"Bearer {raw}"}
        )
    assert recorder.calls == 0


@pytest.mark.parametrize("name", ["Txn-Token", "txn-token", "TXN-TOKEN"])
async def test_caller_supplied_txn_token_header_is_refused(http_shell, current, name) -> None:
    recorder = Recorder(ok)
    shell = http_shell(recorder, TRUSTED)
    with bind_transaction(current), pytest.raises(ConfigurationError):
        await shell.request("GET", "https://ledger.internal/x", headers={name: "attacker.jwt.x"})
    assert recorder.calls == 0


async def test_txn_token_in_client_default_headers_is_refused(http_shell, current) -> None:
    recorder = Recorder(ok)
    transport = httpx.MockTransport(recorder)
    is_async = http_shell.__name__.startswith("Async")
    client_cls = httpx.AsyncClient if is_async else httpx.Client
    http_client = client_cls(transport=transport, headers={TXN_TOKEN_HEADER: "stale.jwt.x"})
    shell = http_shell(recorder, TRUSTED, http_client=http_client)
    with bind_transaction(current), pytest.raises(ConfigurationError):
        await shell.request("GET", "https://ledger.internal/x")
    assert recorder.calls == 0


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/steal",
        "https://ledger.internal.evil.example/",
        "https://sub.ledger.internal/",
        "http://ledger.internal/",
        "https://ledger.internal:8443/",
        "https://risk.internal/",  # listed only on :8443
        "https://ledger.internal@evil.example/",
        "https://user:pw@ledger.internal/",
        "/relative/path",
        "ftp://ledger.internal/",
        "https://[::1/",
    ],
)
async def test_unlisted_destination_is_rejected_before_connecting(http_shell, current, url) -> None:
    recorder = Recorder(ok)
    shell = http_shell(recorder, TRUSTED)
    with bind_transaction(current), pytest.raises(AuthorizationError) as excinfo:
        await shell.request("GET", url)
    assert excinfo.value.reason is ReasonCode.DESTINATION_NOT_TRUSTED
    assert recorder.calls == 0


@pytest.mark.parametrize(
    "url",
    [
        "https://LEDGER.internal/a",
        "https://ledger.internal:443/a",
        "https://ledger.internal./a",
        "https://risk.internal:8443/b?q=1",
    ],
)
async def test_allowlist_matches_normalised_origins(http_shell, current, url) -> None:
    recorder = Recorder(ok)
    shell = http_shell(recorder, TRUSTED)
    with bind_transaction(current):
        await shell.request("GET", url)
    assert recorder.calls == 1


async def test_redirect_to_untrusted_host_is_not_followed(http_shell, current) -> None:
    recorder = Recorder(
        lambda _: httpx.Response(302, headers={"location": "https://evil.example/collect"})
    )
    shell = http_shell(recorder, TRUSTED)
    with bind_transaction(current):
        response = await shell.request("GET", "https://ledger.internal/x")
    assert response.status_code == 302
    assert recorder.calls == 1
    assert all(r.url.host == "ledger.internal" for r in recorder.requests)


async def test_redirect_not_followed_even_if_injected_client_follows(http_shell, current) -> None:
    recorder = Recorder(
        lambda r: (
            httpx.Response(302, headers={"location": "https://evil.example/"})
            if r.url.host == "ledger.internal"
            else httpx.Response(200)
        )
    )
    is_async = http_shell.__name__.startswith("Async")
    client_cls = httpx.AsyncClient if is_async else httpx.Client
    http_client = client_cls(transport=httpx.MockTransport(recorder), follow_redirects=True)
    shell = http_shell(recorder, TRUSTED, http_client=http_client)
    with bind_transaction(current):
        response = await shell.request("GET", "https://ledger.internal/x")
    assert response.status_code == 302
    assert recorder.calls == 1


async def test_missing_transaction_is_refused_before_connecting(http_shell) -> None:
    recorder = Recorder(ok)
    shell = http_shell(recorder, TRUSTED)
    with pytest.raises(TokenError) as excinfo:
        await shell.request("GET", "https://ledger.internal/x")
    assert excinfo.value.reason is ReasonCode.TOKEN_MISSING
    assert recorder.calls == 0


async def test_unbound_call_allowed_when_not_required(http_shell) -> None:
    recorder = Recorder(ok)
    shell = http_shell(recorder, TRUSTED)
    await shell.request("GET", "https://ledger.internal/health", require_transaction=False)
    assert TXN_TOKEN_HEADER not in recorder.requests[0].headers


async def test_destination_check_applies_without_a_transaction(http_shell) -> None:
    recorder = Recorder(ok)
    shell = http_shell(recorder, TRUSTED)
    with pytest.raises(AuthorizationError):
        await shell.request("GET", "https://evil.example/", require_transaction=False)
    assert recorder.calls == 0


async def test_replacer_is_called_and_its_token_is_sent(
    http_shell, factory, verifier, current
) -> None:
    replacement = verifier.verify(factory.mint(txn=current.claims.txn, scope="payments.read"))
    seen = []

    def replacer(token):
        seen.append(token)
        return replacement

    recorder = Recorder(ok)
    shell = http_shell(recorder, TRUSTED, replacer=replacer)
    with bind_transaction(current):
        await shell.request("GET", "https://ledger.internal/x")
    assert seen == [current]
    assert recorder.requests[0].headers[TXN_TOKEN_HEADER] == replacement.forwardable.reveal()


async def test_replacer_not_called_for_untrusted_destination(http_shell, current) -> None:
    seen = []
    shell = http_shell(Recorder(ok), TRUSTED, replacer=lambda t: seen.append(t) or t)
    with bind_transaction(current), pytest.raises(AuthorizationError):
        await shell.request("GET", "https://evil.example/")
    assert seen == []


async def test_replacer_returning_unverified_value_is_refused(http_shell, current) -> None:
    recorder = Recorder(ok)
    shell = http_shell(recorder, TRUSTED, replacer=lambda _: "raw.jwt.value")
    with bind_transaction(current), pytest.raises(TypeError):
        await shell.request("GET", "https://ledger.internal/x")
    assert recorder.calls == 0


@pytest.mark.parametrize(
    ("verb", "kwargs"),
    [
        ("get", {"params": {"q": "1"}}),
        ("post", {"json": {"a": 1}}),
        ("put", {"content": b"raw"}),
        ("patch", {"data": {"f": "v"}}),
        ("delete", {"timeout": 1.0}),
    ],
)
async def test_every_verb_propagates_the_token(http_shell, current, verb, kwargs) -> None:
    recorder = Recorder(ok)
    shell = http_shell(recorder, TRUSTED)
    with bind_transaction(current):
        await shell.verb(verb, "https://ledger.internal/r", **kwargs)
    sent = recorder.requests[0]
    assert sent.method == verb.upper()
    assert sent.headers[TXN_TOKEN_HEADER] == current.forwardable.reveal()


CLIENTS = [TransactionClient, AsyncTransactionClient]


@pytest.mark.parametrize("cls", CLIENTS)
@pytest.mark.parametrize(
    "trusted",
    [
        [],
        "https://ledger.internal",
        ["http://ledger.internal"],
        ["https://ledger.internal/path"],
        ["https://ledger.internal?x=1"],
        ["https://u:p@ledger.internal"],
        ["ledger.internal"],
        ["https://[::1"],
        [""],
    ],
)
def test_invalid_allowlist_is_refused(cls, trusted) -> None:
    with pytest.raises(ConfigurationError):
        cls(trusted)


@pytest.mark.parametrize("cls", CLIENTS)
def test_localhost_http_allowed_only_with_flag(cls) -> None:
    with pytest.raises(ConfigurationError):
        cls(["http://localhost:8000"])
    with pytest.raises(ConfigurationError):
        cls(["http://ledger.internal"], allow_insecure_localhost=True)
    client = cls(
        ["http://localhost:8000", "https://LEDGER.internal/"], allow_insecure_localhost=True
    )
    assert client.trusted_destinations == frozenset(
        {"http://localhost:8000", "https://ledger.internal:443"}
    )
    assert "ledger.internal" in repr(client)


@pytest.mark.parametrize("cls", CLIENTS)
def test_non_positive_timeout_is_refused(cls) -> None:
    with pytest.raises(ConfigurationError):
        cls(TRUSTED, timeout=0)


def test_sync_client_closes_only_what_it_owns() -> None:
    with TransactionClient(TRUSTED) as owned:
        pass
    assert owned._http.is_closed
    injected = httpx.Client()
    with TransactionClient(TRUSTED, http_client=injected):
        pass
    assert not injected.is_closed
    injected.close()


async def test_async_client_closes_only_what_it_owns() -> None:
    async with AsyncTransactionClient(TRUSTED) as owned:
        pass
    assert owned._http.is_closed
    injected = httpx.AsyncClient()
    async with AsyncTransactionClient(TRUSTED, http_client=injected):
        pass
    assert not injected.is_closed
    await injected.aclose()


class _CopyTokenToAuthorization(httpx.Auth):
    def auth_flow(self, request):
        request.headers["Authorization"] = f"Bearer {request.headers['Txn-Token']}"
        yield request


class _RedirectingAuth(httpx.Auth):
    def auth_flow(self, request):
        request.url = httpx.URL("https://attacker.example/steal")
        yield request


class _ChallengeAuth(httpx.Auth):
    """Two-step flow: first request unauthenticated, then retry with a header."""

    def auth_flow(self, request):
        response = yield request
        if response.status_code == 401:
            request.headers["X-Workload-Proof"] = "proof"
            yield request


def _guard_client(auth: httpx.Auth, sent: list[httpx.Request]):
    from pytrat.client import TransactionClient

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        status = 401 if "X-Workload-Proof" not in request.headers and len(sent) == 1 else 200
        return httpx.Response(status)

    return TransactionClient(
        ["https://ledger.internal"],
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        auth=auth,
    )


def test_auth_flow_copying_token_into_authorization_is_blocked() -> None:
    from pytrat.client import bind_transaction
    from pytrat.core import ConfigurationError
    from pytrat.core.testing import TokenFactory

    factory = TokenFactory.create()
    sent: list[httpx.Request] = []
    client = _guard_client(_CopyTokenToAuthorization(), sent)
    with (
        bind_transaction(factory.verifier().verify(factory.mint())),
        pytest.raises(ConfigurationError),
    ):
        client.post("https://ledger.internal/entries")
    assert sent == []


def test_auth_flow_redirecting_to_untrusted_host_is_blocked() -> None:
    from pytrat.client import bind_transaction
    from pytrat.core import AuthorizationError, ReasonCode
    from pytrat.core.testing import TokenFactory

    factory = TokenFactory.create()
    sent: list[httpx.Request] = []
    client = _guard_client(_RedirectingAuth(), sent)
    with (
        bind_transaction(factory.verifier().verify(factory.mint())),
        pytest.raises(AuthorizationError) as excinfo,
    ):
        client.post("https://ledger.internal/entries")
    assert excinfo.value.reason is ReasonCode.DESTINATION_NOT_TRUSTED
    assert sent == []


def test_multi_step_auth_flow_is_supported_and_checked_each_step() -> None:
    from pytrat.client import bind_transaction
    from pytrat.core.testing import TokenFactory

    factory = TokenFactory.create()
    sent: list[httpx.Request] = []
    client = _guard_client(_ChallengeAuth(), sent)
    with bind_transaction(factory.verifier().verify(factory.mint())):
        response = client.post("https://ledger.internal/entries")
    assert response.status_code == 200
    assert len(sent) == 2
    assert all("Txn-Token" in request.headers for request in sent)


async def test_async_auth_flow_copying_token_into_authorization_is_blocked() -> None:
    from pytrat.client import AsyncTransactionClient, bind_transaction
    from pytrat.core import ConfigurationError
    from pytrat.core.testing import TokenFactory

    factory = TokenFactory.create()
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200)

    client = AsyncTransactionClient(
        ["https://ledger.internal"],
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        auth=_CopyTokenToAuthorization(),
    )
    with (
        bind_transaction(factory.verifier().verify(factory.mint())),
        pytest.raises(ConfigurationError),
    ):
        await client.post("https://ledger.internal/entries")
    assert sent == []


async def test_async_multi_step_auth_flow() -> None:
    from pytrat.client import AsyncTransactionClient, bind_transaction
    from pytrat.core.testing import TokenFactory

    factory = TokenFactory.create()
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(401 if len(sent) == 1 else 200)

    client = AsyncTransactionClient(
        ["https://ledger.internal"],
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        auth=_ChallengeAuth(),
    )
    with bind_transaction(factory.verifier().verify(factory.mint())):
        response = await client.post("https://ledger.internal/entries")
    assert response.status_code == 200
    assert len(sent) == 2
