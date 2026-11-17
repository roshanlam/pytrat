"""The real exchange client against the real reference TTS, in-process (txn-tokens-11 §11, §13.15).

No mocks: the client signs RFC 7523 assertions, the TTS authenticates them, validates the subject
access token, applies issuance policy, signs, and the client verifies the result against the
TTS's published JWKS.
"""

from __future__ import annotations

import json
import os
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest

from pytrat.client import (
    AsyncTransactionTokenClient,
    ExchangeError,
    PrivateKeyJwtCredential,
)
from pytrat.core import (
    AuthorizationError,
    MemorySink,
    ReasonCode,
    Scope,
    SecretToken,
    StaticKeySet,
    TokenVerifier,
    VerifiedToken,
    VerifierSettings,
)
from pytrat.core.constants import TOKEN_TYPE_ACCESS_TOKEN
from pytrat.core.crypto import private_key_to_pem, sign_compact
from pytrat.core.testing import FrozenClock, TestKey, generate_test_key
from pytrat.server import build_components, create_app, parse_settings

pytestmark = pytest.mark.integration

TRUST_DOMAIN = "payments.internal"
TOKEN_ENDPOINT = "https://tts.payments.internal/token"
IDP = "https://idp.example"
API = "https://api.payments.example"
NOW = 1_795_000_000


def _secret(path: Path, data: bytes) -> Path:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    return path


@dataclass
class Lab:
    clock: FrozenClock
    idp: TestKey
    tts_sink: MemorySink
    gateway: AsyncTransactionTokenClient
    payment: AsyncTransactionTokenClient

    def access_token(self, **overrides: object) -> SecretToken:
        now = int(self.clock.now())
        claims = {
            "iss": IDP,
            "aud": API,
            "sub": "user:123",
            "scope": "payments.transfer payments.read",
            "iat": now,
            "exp": now + 600,
            "client_id": "web-app",
            **overrides,
        }
        return SecretToken(
            sign_compact(claims, self.idp.private_key, alg="ES256", kid=self.idp.kid, typ="at+jwt")
        )

    async def issue(self, **details: object) -> VerifiedToken:
        return await self.gateway.issue(
            audience=TRUST_DOMAIN,
            scope="payments.transfer",
            subject_token=self.access_token(),
            subject_token_type=TOKEN_TYPE_ACCESS_TOKEN,
            request_details=details
            or {
                "source_account": "account-A",
                "destination_account": "account-B",
                "amount_minor": 10000,
                "currency": "USD",
            },
            request_context={"req_ip": "203.0.113.7"},
        )


@pytest.fixture
async def lab(tmp_path: Path) -> AsyncIterator[Lab]:
    clock = FrozenClock(NOW)
    tts_key, idp = generate_test_key("ES256", kid="tts-1"), generate_test_key("ES256", kid="idp-1")
    gateway_key = generate_test_key("ES256", kid="gw-1")
    payment_key = generate_test_key("ES256", kid="pay-1")
    _secret(tmp_path / "tts.pem", private_key_to_pem(tts_key.private_key))
    gateway_pem = _secret(tmp_path / "gw.pem", private_key_to_pem(gateway_key.private_key))
    payment_pem = _secret(tmp_path / "pay.pem", private_key_to_pem(payment_key.private_key))
    (tmp_path / "idp.json").write_text(json.dumps({"keys": [idp.jwk()]}))
    settings = parse_settings(
        {
            "trust_domain": TRUST_DOMAIN,
            "issuer": "https://tts.payments.internal",
            "token_endpoint": TOKEN_ENDPOINT,
            "signing_keys": [
                {"kid": "tts-1", "alg": "ES256", "private_key_path": "tts.pem", "state": "active"}
            ],
            "workloads": [
                {"id": "api-gateway", "jwks": {"keys": [gateway_key.jwk()]}},
                {"id": "payment-service", "jwks": {"keys": [payment_key.jwk()]}},
            ],
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
                        "rctx": {"req_ip": "string"},
                    },
                    "payment-service": {
                        "scopes": ["payments.transfer", "payments.read"],
                        "may_replace": True,
                    },
                }
            },
        },
        base_dir=tmp_path,
    )
    sink = MemorySink()
    components = build_components(settings, clock=clock, sink=sink)
    app = create_app(components)
    verifier = TokenVerifier(
        VerifierSettings(
            trust_domain=TRUST_DOMAIN, expected_issuer="https://tts.payments.internal"
        ),
        StaticKeySet.from_jwks(components.signer.jwks()),
        clock,
    )

    def client(workload: str, pem: Path, kid: str) -> AsyncTransactionTokenClient:
        http = httpx.AsyncClient(transport=httpx.ASGITransport(app=app))
        credential = PrivateKeyJwtCredential(
            workload, pem, alg="ES256", kid=kid, token_endpoint=TOKEN_ENDPOINT, clock=clock
        )
        return AsyncTransactionTokenClient(TOKEN_ENDPOINT, credential, verifier, http_client=http)

    gateway = client("api-gateway", gateway_pem, "gw-1")
    payment = client("payment-service", payment_pem, "pay-1")
    async with gateway, payment:
        yield Lab(clock=clock, idp=idp, tts_sink=sink, gateway=gateway, payment=payment)


async def test_issued_token_carries_authoritative_context(lab: Lab) -> None:
    """txn-tokens-11 §11.4 response, §9.2 claims, §9.2.3 TTS-authoritative tctx."""
    token = await lab.issue()
    claims = token.claims
    assert claims.aud == TRUST_DOMAIN
    assert claims.sub == "user:123"
    assert str(claims.scope) == "payments.transfer"
    assert claims.req_wl == "api-gateway"
    assert claims.tctx == {
        "source_account": "account-A",
        "destination_account": "account-B",
        "amount_minor": 10000,
        "currency": "USD",
    }
    assert claims.rctx is not None
    assert claims.rctx["req_ip"] == "203.0.113.7"
    assert claims.exp - claims.iat <= 60


async def test_request_details_cannot_set_identity_claims(lab: Lab) -> None:
    """tctx is built by the TTS from an allowlist; requesters cannot inject sub/txn/aud."""
    token = await lab.issue(
        source_account="account-A",
        destination_account="account-B",
        amount_minor=10000,
        currency="USD",
        sub="user:admin",
        txn="attacker-txn",
    )
    assert token.claims.sub == "user:123"
    assert token.claims.txn != "attacker-txn"
    assert token.claims.tctx is not None
    assert "sub" not in token.claims.tctx


async def test_downstream_replacement_attenuates_and_preserves_immutables(lab: Lab) -> None:
    """txn-tokens-11 §13.15: txn, sub and aud never change; scope may only shrink."""
    original = await lab.issue()
    narrowed = await lab.payment.replace(original, Scope.of("payments.transfer"))
    assert (narrowed.claims.txn, narrowed.claims.sub, narrowed.claims.aud) == (
        original.claims.txn,
        original.claims.sub,
        original.claims.aud,
    )
    assert narrowed.claims.tctx == original.claims.tctx
    assert narrowed.claims.exp <= original.claims.exp
    assert [e.event_type.value for e in lab.tts_sink.events] == ["token.issued", "token.replaced"]


async def test_replacement_cannot_widen_scope(lab: Lab) -> None:
    original = await lab.issue()
    with pytest.raises(AuthorizationError) as excinfo:
        await lab.payment.replace(original, Scope.of("payments.transfer", "payments.read"))
    assert excinfo.value.reason is ReasonCode.REPLACEMENT_WIDENS_AUTHORIZATION


async def test_expired_token_cannot_be_replaced(lab: Lab) -> None:
    """txn-tokens-11 §13.15: the TTS MUST NOT replace an expired token."""
    original = await lab.issue()
    lab.clock.advance(61)
    with pytest.raises(ExchangeError) as excinfo:
        await lab.payment.replace(original)
    assert excinfo.value.oauth_error == "invalid_grant"


async def test_unauthorized_scope_is_refused(lab: Lab) -> None:
    with pytest.raises(ExchangeError) as excinfo:
        await lab.gateway.issue(
            audience=TRUST_DOMAIN,
            scope="ledger.admin",
            subject_token=lab.access_token(),
            subject_token_type=TOKEN_TYPE_ACCESS_TOKEN,
        )
    assert excinfo.value.oauth_error == "invalid_scope"


async def test_expired_subject_token_is_refused(lab: Lab) -> None:
    """txn-tokens-11 §6: the TTS MUST NOT issue for an expired subject credential."""
    with pytest.raises(ExchangeError) as excinfo:
        await lab.gateway.issue(
            audience=TRUST_DOMAIN,
            scope="payments.transfer",
            subject_token=lab.access_token(exp=NOW - 1),
            subject_token_type=TOKEN_TYPE_ACCESS_TOKEN,
        )
    assert excinfo.value.oauth_error == "invalid_grant"


async def test_gateway_cannot_replace_without_permission(lab: Lab) -> None:
    original = await lab.issue()
    with pytest.raises(ExchangeError) as excinfo:
        await lab.gateway.replace(original)
    assert excinfo.value.oauth_error in {"unauthorized_client", "invalid_grant"}
