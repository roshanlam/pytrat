"""Problem+json shape, debug detail, and JWKS key refresh at the dependency."""

from datetime import timedelta

import httpx
import pytest
from starlette.requests import Request

from _fastapi_testkit import TCTX, Kit, ledger_app, serve
from pytrat.client import AsyncJwksRefresher
from pytrat.core import (
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    ReasonCode,
    TokenError,
    TokenVerifier,
    VerifierSettings,
)
from pytrat.core.testing import generate_test_key
from pytrat.fastapi import exception_handler, problem_body
from pytrat.fastapi.responses import problem_headers

BODY = dict(TCTX)


async def test_problem_json_shape(kit: Kit) -> None:
    pytrat = kit.pytrat()
    app, _ = ledger_app(pytrat)
    async with serve(app, pytrat) as client:
        response = await client.post(
            "/internal/transfer", json=BODY, headers=kit.headers(caller="intruder")
        )
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json() == {
        "type": "urn:pytrat:problem:CALLER_NOT_ALLOWED",
        "title": "Transaction not authorized",
        "status": 403,
        "reason_code": "CALLER_NOT_ALLOWED",
        "transaction_id": response.json()["transaction_id"],
    }
    assert "detail" not in response.json()


async def test_debug_includes_the_value_free_detail(kit: Kit) -> None:
    pytrat = kit.pytrat(debug=True)
    app, _ = ledger_app(pytrat)
    async with serve(app, pytrat) as client:
        response = await client.post(
            "/internal/transfer", json={**BODY, "amount_minor": 5}, headers=kit.headers()
        )
    detail = response.json()["detail"]
    assert "amount_minor" in detail
    assert "5" not in detail.replace("amount_minor", "")


def test_problem_headers() -> None:
    assert problem_headers(TokenError(ReasonCode.TOKEN_EXPIRED, "x")) == {
        "WWW-Authenticate": "Txn-Token"
    }
    assert problem_headers(AuthenticationError(ReasonCode.SUBJECT_TOKEN_INVALID, "x")) == {
        "WWW-Authenticate": "Bearer"
    }
    assert problem_headers(AuthenticationError(ReasonCode.WORKLOAD_UNAUTHENTICATED, "x")) == {}
    assert problem_headers(AuthorizationError(ReasonCode.SCOPE_INSUFFICIENT, "x")) == {}
    assert problem_body(ConfigurationError("x"))["status"] == 500


async def test_exception_handler_rejects_foreign_exceptions() -> None:
    handle = exception_handler()
    request = Request({"type": "http", "path": "/", "headers": []})
    with pytest.raises(ValueError, match="boom"):
        await handle(request, ValueError("boom"))


async def test_unknown_kid_triggers_a_jwks_refresh(kit: Kit) -> None:
    rotated = generate_test_key("ES256")
    jwks_calls: list[int] = []

    def jwks(request: httpx.Request) -> httpx.Response:
        jwks_calls.append(1)
        keys = [kit.factory.key.jwk()] + ([rotated.jwk()] if len(jwks_calls) > 1 else [])
        return httpx.Response(200, json={"keys": keys})

    refresher = AsyncJwksRefresher(
        "https://tts.internal/jwks",
        clock=kit.factory.clock,
        min_refresh_interval=timedelta(seconds=1),
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(jwks)),
    )
    verifier = TokenVerifier(
        VerifierSettings(trust_domain=kit.factory.trust_domain, algorithms=frozenset({"ES256"})),
        refresher.keys,
        clock=kit.factory.clock,
    )
    pytrat = kit.pytrat(verifier=verifier, jwks_refresher=refresher)
    app, _ = ledger_app(pytrat)
    async with serve(app, pytrat) as client:
        assert jwks_calls == [1]  # loaded at startup
        known = await client.post("/internal/transfer", json=BODY, headers=kit.headers())
        kit.factory.clock.advance(2)
        new_key_token = kit.factory.mint(key=rotated)
        rotated_response = await client.post(
            "/internal/transfer", json=BODY, headers=kit.headers(new_key_token)
        )
        garbage = await client.post(
            "/internal/transfer", json=BODY, headers=kit.headers("not-a-token")
        )
        missing = await client.post("/internal/transfer", json=BODY, headers=kit.headers(""))
    assert known.status_code == 200
    assert rotated_response.status_code == 200
    assert garbage.json()["reason_code"] == "TOKEN_MALFORMED"
    assert missing.json()["reason_code"] == "TOKEN_MISSING"
    assert len(jwks_calls) == 2
    await refresher.aclose()


def test_jwks_refresher_requires_a_token_verifier(kit: Kit) -> None:
    refresher = AsyncJwksRefresher("https://tts.internal/jwks")
    with pytest.raises(ConfigurationError, match="TokenVerifier"):
        kit.pytrat(verifier=kit.factory.verifier().verify, jwks_refresher=refresher)
