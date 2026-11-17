"""TransactionTokenClient / AsyncTransactionTokenClient, run against both shells."""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
from urllib.parse import parse_qs

import httpx
import pytest

from _client_testkit import TOKEN_ENDPOINT, Recorder, StaticCredential, tts_error, tts_success
from pytrat.client import (
    AsyncTransactionTokenClient,
    ExchangeError,
    MtlsCredential,
    TransactionTokenClient,
)
from pytrat.core import (
    AuthorizationError,
    ConfigurationError,
    DependencyError,
    ReasonCode,
    Scope,
    SecretToken,
    TokenError,
)
from pytrat.core.constants import TOKEN_TYPE_ACCESS_TOKEN, TOKEN_TYPE_TXN_TOKEN
from pytrat.core.testing import generate_test_key

SUBJECT = SecretToken("inbound-access-token-123")
ISSUE = {
    "audience": "payments.internal",
    "scope": "payments.transfer",
    "subject_token": SUBJECT,
    "subject_token_type": TOKEN_TYPE_ACCESS_TOKEN,
}


def _form(request: httpx.Request) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(request.content.decode()).items()}


async def test_issue_sends_form_and_returns_locally_verified_token(
    token_shell, factory, verifier
) -> None:
    raw = factory.mint()
    recorder = Recorder(lambda _: tts_success(raw))
    shell = token_shell(recorder, verifier)
    token = await shell.issue(**ISSUE, request_context={"ip": "10.0.0.1"})
    assert token.forwardable.reveal() == raw
    assert token.claims.aud == "payments.internal"
    (sent,) = recorder.requests
    assert sent.method == "POST"
    assert str(sent.url) == TOKEN_ENDPOINT
    assert sent.headers["content-type"] == "application/x-www-form-urlencoded"
    form = _form(sent)
    assert form["subject_token"] == SUBJECT.reveal()
    assert form["client_id"] == "gateway"
    assert form["request_context"] == '{"ip":"10.0.0.1"}'
    assert "authorization" not in sent.headers


async def test_tts_response_with_forged_token_is_rejected(token_shell, factory, verifier) -> None:
    impostor = generate_test_key("ES256", kid=factory.key.kid)
    forged = factory.mint(key=impostor)
    shell = token_shell(Recorder(lambda _: tts_success(forged)), verifier)
    with pytest.raises(TokenError) as excinfo:
        await shell.issue(**ISSUE)
    assert excinfo.value.reason is ReasonCode.SIGNATURE_INVALID


async def test_tts_token_for_another_trust_domain_is_rejected(
    token_shell, factory, verifier
) -> None:
    other = factory.mint(aud="ledger.internal")
    shell = token_shell(Recorder(lambda _: tts_success(other)), verifier)
    with pytest.raises(TokenError) as excinfo:
        await shell.issue(**ISSUE)
    assert excinfo.value.reason is ReasonCode.TRUST_DOMAIN_MISMATCH


async def test_tts_response_with_refresh_token_is_rejected_section_11_4(
    token_shell, factory, verifier
) -> None:
    raw = factory.mint()
    shell = token_shell(Recorder(lambda _: tts_success(raw, refresh_token="rt")), verifier)
    with pytest.raises(ExchangeError) as excinfo:
        await shell.issue(**ISSUE)
    assert excinfo.value.reason is ReasonCode.EXCHANGE_FAILED


async def test_refresh_token_subject_is_refused_without_contacting_tts(
    token_shell, verifier
) -> None:
    recorder = Recorder(lambda _: httpx.Response(500))
    shell = token_shell(recorder, verifier)
    with pytest.raises(ExchangeError) as excinfo:
        await shell.issue(
            **{**ISSUE, "subject_token_type": "urn:ietf:params:oauth:token-type:refresh_token"}
        )
    assert excinfo.value.reason is ReasonCode.SUBJECT_TOKEN_INVALID
    assert recorder.calls == 0


async def test_tts_redirect_is_not_followed(token_shell, verifier) -> None:
    recorder = Recorder(
        lambda _: httpx.Response(307, headers={"location": "https://evil.example/token"})
    )
    shell = token_shell(recorder, verifier)
    with pytest.raises(ExchangeError) as excinfo:
        await shell.issue(**ISSUE)
    assert excinfo.value.status_code == 307
    assert recorder.calls == 1


async def test_oauth_error_from_tts_is_mapped(token_shell, verifier) -> None:
    shell = token_shell(Recorder(lambda _: tts_error(400, "invalid_grant", "expired")), verifier)
    with pytest.raises(ExchangeError) as excinfo:
        await shell.issue(**ISSUE)
    assert excinfo.value.oauth_error == "invalid_grant"
    assert excinfo.value.oauth_error_description == "expired"


async def test_secrets_absent_from_repr_and_errors(token_shell, verifier) -> None:
    def echo(request: httpx.Request) -> httpx.Response:
        return tts_error(400, "invalid_grant", f"rejected {_form(request)['subject_token']}")

    shell = token_shell(Recorder(echo), verifier)
    with pytest.raises(ExchangeError) as excinfo:
        await shell.issue(**ISSUE)
    error = excinfo.value
    for rendered in (
        str(error),
        repr(error),
        str(error.oauth_error_description),
        repr(shell.client),
    ):
        assert SUBJECT.reveal() not in rendered


async def test_network_failure_is_a_dependency_error(token_shell, verifier) -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    shell = token_shell(Recorder(boom), verifier)
    with pytest.raises(DependencyError) as excinfo:
        await shell.issue(**ISSUE)
    assert excinfo.value.reason is ReasonCode.DEPENDENCY_UNAVAILABLE


async def test_oversized_tts_response_is_rejected(token_shell, verifier) -> None:
    huge = httpx.Response(
        200, content=b"x" * (70 * 1024), headers={"content-type": "application/json"}
    )
    shell = token_shell(Recorder(lambda _: huge), verifier)
    with pytest.raises(ExchangeError, match="size"):
        await shell.issue(**ISSUE)


async def test_replace_presents_current_token_and_verifies_reply(
    token_shell, factory, verifier, current
) -> None:
    narrower = factory.mint(txn=current.claims.txn, scope="payments.read")
    recorder = Recorder(lambda _: tts_success(narrower))
    shell = token_shell(recorder, verifier)
    replaced = await shell.replace(current, scope=Scope.of("payments.read"))
    assert replaced.claims.scope == Scope.of("payments.read")
    form = _form(recorder.requests[0])
    assert form["subject_token"] == current.forwardable.reveal()
    assert form["subject_token_type"] == TOKEN_TYPE_TXN_TOKEN
    assert form["audience"] == current.claims.aud


async def test_replacement_request_cannot_widen_scope(token_shell, verifier, current) -> None:
    recorder = Recorder(lambda _: httpx.Response(500))
    shell = token_shell(recorder, verifier)
    with pytest.raises(AuthorizationError) as excinfo:
        await shell.replace(current, scope=Scope.of("payments.read", "admin.all"))
    assert excinfo.value.reason is ReasonCode.REPLACEMENT_WIDENS_AUTHORIZATION
    assert recorder.calls == 0


async def test_tts_replacement_that_widens_scope_is_rejected(
    token_shell, factory, verifier, current
) -> None:
    wider = factory.mint(txn=current.claims.txn, scope="payments.read payments.transfer admin")
    shell = token_shell(Recorder(lambda _: tts_success(wider)), verifier)
    with pytest.raises(AuthorizationError) as excinfo:
        await shell.replace(current)
    assert excinfo.value.reason is ReasonCode.REPLACEMENT_WIDENS_AUTHORIZATION


async def test_tts_replacement_with_swapped_transaction_is_rejected(
    token_shell, factory, verifier, current
) -> None:
    swapped = factory.mint(txn="txn-other", scope="payments.read")
    shell = token_shell(Recorder(lambda _: tts_success(swapped)), verifier)
    with pytest.raises(AuthorizationError):
        await shell.replace(current)


# ----------------------------------------------------------------------------- configuration

CLIENTS = [TransactionTokenClient, AsyncTransactionTokenClient]


@pytest.mark.parametrize("cls", CLIENTS)
@pytest.mark.parametrize(
    ("endpoint", "insecure"),
    [
        ("http://tts.internal/token", False),
        ("http://tts.internal/token", True),
        ("http://localhost:8080/token", False),
        ("https://user:pw@tts.internal/token", False),
        ("https://tts.internal/token#frag", False),
        ("tts.internal/token", False),
        ("ftp://tts.internal/token", False),
        ("https://[::1", False),
        ("", False),
    ],
)
def test_insecure_or_malformed_token_endpoint_is_refused(cls, verifier, endpoint, insecure) -> None:
    with pytest.raises(ConfigurationError):
        cls(endpoint, StaticCredential(), verifier, allow_insecure_localhost=insecure)


@pytest.mark.parametrize("cls", CLIENTS)
@pytest.mark.parametrize(
    "endpoint", ["http://localhost:8080/token", "http://127.0.0.1/token", "http://[::1]:9/token"]
)
def test_plain_http_allowed_only_for_localhost_with_flag(cls, verifier, endpoint) -> None:
    client = cls(endpoint, StaticCredential(), verifier, allow_insecure_localhost=True)
    assert "localhost" in repr(client) or "127.0.0.1" in repr(client) or "::1" in repr(client)


@pytest.mark.parametrize("cls", CLIENTS)
def test_invalid_verifier_or_timeout_is_refused(cls, verifier) -> None:
    with pytest.raises(ConfigurationError):
        cls(TOKEN_ENDPOINT, StaticCredential(), object())
    with pytest.raises(ConfigurationError):
        cls(TOKEN_ENDPOINT, StaticCredential(), verifier, timeout=0)


def test_sync_client_closes_only_the_http_client_it_created(verifier) -> None:
    with TransactionTokenClient(TOKEN_ENDPOINT, StaticCredential(), verifier) as owned:
        pass
    assert owned._http.is_closed
    injected = httpx.Client()
    with TransactionTokenClient(TOKEN_ENDPOINT, StaticCredential(), verifier, http_client=injected):
        pass
    assert not injected.is_closed
    injected.close()


async def test_async_client_closes_only_the_http_client_it_created(verifier) -> None:
    async with AsyncTransactionTokenClient(TOKEN_ENDPOINT, StaticCredential(), verifier) as owned:
        pass
    assert owned._http.is_closed
    injected = httpx.AsyncClient()
    async with AsyncTransactionTokenClient(
        TOKEN_ENDPOINT, StaticCredential(), verifier, http_client=injected
    ):
        pass
    assert not injected.is_closed
    await injected.aclose()


@pytest.mark.parametrize("cls", CLIENTS)
async def test_mtls_credential_configures_self_built_transport(cls, verifier, monkeypatch) -> None:
    context = ssl.create_default_context()
    calls = []

    def fake_ssl_context(self: MtlsCredential) -> ssl.SSLContext:
        calls.append(self)
        return context

    monkeypatch.setattr(MtlsCredential, "ssl_context", fake_ssl_context)
    credential = MtlsCredential("cert.pem", "key.pem", client_id="gateway")
    client = cls(TOKEN_ENDPOINT, credential, verifier)
    assert calls == [credential]
    if isinstance(client, AsyncTransactionTokenClient):
        await client.aclose()
    else:
        client.close()


def test_issued_token_digest_is_logged_never_the_token(
    token_shell, factory, verifier, caplog
) -> None:
    raw = factory.mint()
    shell = token_shell(Recorder(lambda _: tts_success(raw)), verifier)
    with caplog.at_level(logging.DEBUG, logger="pytrat.client"):
        token = asyncio.run(shell.issue(**ISSUE))
    assert raw not in caplog.text
    assert token.digest in caplog.text
    assert json.dumps(raw) not in caplog.text
