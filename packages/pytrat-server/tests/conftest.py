from __future__ import annotations

import copy
import json
import os
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlencode

import httpx
import pytest
from fastapi import FastAPI

from pytrat.core import MemorySink, StaticKeySet, TokenVerifier, VerifierSettings
from pytrat.core.constants import (
    CLIENT_ASSERTION_TYPE_JWT_BEARER,
    GRANT_TYPE_TOKEN_EXCHANGE,
    TOKEN_TYPE_ACCESS_TOKEN,
    TOKEN_TYPE_TXN_TOKEN,
)
from pytrat.core.crypto import private_key_to_pem, sign_compact
from pytrat.core.testing import FrozenClock, TestKey, generate_test_key
from pytrat.server import (
    InMemoryIssuanceLog,
    TtsComponents,
    TtsSettings,
    build_components,
    create_app,
    parse_settings,
)

TRUST_DOMAIN = "payments.internal"
ISSUER = "https://tts.payments.internal"
TOKEN_ENDPOINT = "https://tts.payments.internal/token"
IDP = "https://idp.test"
API_AUDIENCE = "https://api.payments.example"
NOW = 1_795_000_000

type Mutator = Callable[[dict[str, object]], None]


@pytest.fixture(scope="session")
def keys() -> dict[str, TestKey]:
    return {
        "tts": generate_test_key("ES256", kid="tts-1"),
        "tts-old": generate_test_key("ES256", kid="tts-0"),
        "api-gateway": generate_test_key("ES256", kid="gw-1"),
        "payment-service": generate_test_key("ES256", kid="pay-1"),
        "billing-agent": generate_test_key("ES256", kid="agent-1"),
        "idp": generate_test_key("ES256", kid="idp-1"),
        "attacker": generate_test_key("ES256", kid="gw-1"),
    }


def write_secret(path: Path, data: bytes) -> Path:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    return path


def write_jwks(path: Path, *test_keys: TestKey) -> Path:
    path.write_text(json.dumps({"keys": [key.jwk() for key in test_keys]}))
    return path


def base_config(tmp_path: Path, keys: Mapping[str, TestKey]) -> dict[str, object]:
    write_secret(tmp_path / "tts.pem", private_key_to_pem(keys["tts"].private_key))
    write_secret(tmp_path / "tts-old.pem", private_key_to_pem(keys["tts-old"].private_key))
    write_jwks(tmp_path / "idp.json", keys["idp"])
    write_jwks(tmp_path / "gateway.json", keys["api-gateway"])
    return {
        "trust_domain": TRUST_DOMAIN,
        "issuer": ISSUER,
        "token_endpoint": TOKEN_ENDPOINT,
        "token_lifetime_seconds": 60,
        "algorithms": ["ES256"],
        "signing_keys": [
            {"kid": "tts-1", "alg": "ES256", "private_key_path": "tts.pem", "state": "active"},
            {
                "kid": "tts-0",
                "alg": "ES256",
                "private_key_path": "tts-old.pem",
                "state": "retiring",
            },
        ],
        "workloads": [
            {"id": "api-gateway", "jwks_path": "gateway.json"},
            {"id": "payment-service", "jwks": {"keys": [keys["payment-service"].jwk()]}},
            {"id": "billing-agent", "jwks": {"keys": [keys["billing-agent"].jwk()]}},
        ],
        "subject_tokens": {
            "jwt_access_token": [
                {"issuer": IDP, "jwks_path": "idp.json", "audience": API_AUDIENCE}
            ],
            "self_signed": {"enabled": True},
            "unsigned_json": {"allowed_workloads": ["payment-service"]},
        },
        "issuance_policy": {
            "workloads": {
                "api-gateway": {
                    "scopes": ["payments.transfer", "payments.read"],
                    "audiences": [TRUST_DOMAIN],
                    "tctx": {
                        "source_account": "string",
                        "destination_account": "string",
                        "amount_minor": "integer",
                        "currency": "string",
                    },
                    "rctx": {"req_ip": "string"},
                },
                "payment-service": {
                    "scopes": ["payments.transfer", "payments.read", "ledger.write"],
                    "rctx": {"req_ip": "string", "hop": "string"},
                    "may_replace": True,
                },
                "billing-agent": {
                    "scopes": ["payments.transfer", "payments.read"],
                    "may_replace": True,
                },
            }
        },
        "rate_limit": {"requests_per_second": 1000, "burst": 1000},
    }


@dataclass
class Tts:
    clock: FrozenClock
    settings: TtsSettings
    components: TtsComponents
    app: FastAPI
    sink: MemorySink
    log: InMemoryIssuanceLog
    keys: Mapping[str, TestKey]

    @property
    def now(self) -> int:
        return int(self.clock.now())

    def assertion(
        self, workload: str = "api-gateway", key: TestKey | None = None, **overrides: object
    ) -> str:
        claims: dict[str, object] = {
            "iss": workload,
            "sub": workload,
            "aud": TOKEN_ENDPOINT,
            "iat": self.now,
            "exp": self.now + 60,
            "jti": uuid.uuid4().hex,
        }
        for name, value in overrides.items():
            if value is None:
                claims.pop(name, None)
            else:
                claims[name] = value
        signer = key or self.keys[workload]
        return sign_compact(claims, signer.private_key, alg=signer.alg, kid=signer.kid, typ="JWT")

    def access_token(
        self, key: TestKey | None = None, typ: str = "at+jwt", **overrides: object
    ) -> str:
        claims: dict[str, object] = {
            "iss": IDP,
            "aud": API_AUDIENCE,
            "sub": "user:alice",
            "scope": "payments.transfer payments.read",
            "iat": self.now,
            "exp": self.now + 300,
            "client_id": "web-app",
            "amr": ["pwd", "otp"],
        }
        for name, value in overrides.items():
            if value is None:
                claims.pop(name, None)
            else:
                claims[name] = value
        signer = key or self.keys["idp"]
        return sign_compact(claims, signer.private_key, alg=signer.alg, kid=signer.kid, typ=typ)

    def form(
        self,
        *,
        workload: str = "api-gateway",
        subject_token: str | None = None,
        subject_token_type: str = TOKEN_TYPE_ACCESS_TOKEN,
        authenticate: bool = True,
        **params: object,
    ) -> dict[str, str]:
        data: dict[str, str] = {
            "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
            "requested_token_type": TOKEN_TYPE_TXN_TOKEN,
            "audience": TRUST_DOMAIN,
            "scope": "payments.transfer",
            "subject_token": subject_token or self.access_token(),
            "subject_token_type": subject_token_type,
        }
        if authenticate:
            data["client_assertion_type"] = CLIENT_ASSERTION_TYPE_JWT_BEARER
            data["client_assertion"] = self.assertion(workload)
        for name, value in params.items():
            if value is None:
                data.pop(name, None)
            elif isinstance(value, Mapping):
                data[name] = json.dumps(value)
            else:
                data[name] = str(value)
        return data

    def replacement_form(
        self, txn_token: str, workload: str = "payment-service", **params: object
    ) -> dict[str, str]:
        return self.form(
            workload=workload,
            subject_token=txn_token,
            subject_token_type=TOKEN_TYPE_TXN_TOKEN,
            **params,
        )

    async def post(
        self,
        data: Mapping[str, str] | bytes,
        *,
        headers: Mapping[str, str] | None = None,
        client: tuple[str, int] = ("127.0.0.1", 50000),
    ) -> httpx.Response:
        body = data if isinstance(data, bytes) else urlencode(data).encode()
        request_headers = {"content-type": "application/x-www-form-urlencoded", **(headers or {})}
        transport = httpx.ASGITransport(app=self.app, client=client)
        async with httpx.AsyncClient(transport=transport, base_url="https://tts.test") as http:
            return await http.post("/token", content=body, headers=request_headers)

    async def get(self, path: str) -> httpx.Response:
        transport = httpx.ASGITransport(app=self.app)
        async with httpx.AsyncClient(transport=transport, base_url="https://tts.test") as http:
            return await http.get(path)

    async def issue(self, **form: object) -> str:
        response = await self.post(self.form(**form))  # type: ignore[arg-type]
        assert response.status_code == 200, response.text
        return str(response.json()["access_token"])

    def verifier(self, jwks: Mapping[str, object] | None = None) -> TokenVerifier:
        return TokenVerifier(
            VerifierSettings(
                trust_domain=TRUST_DOMAIN,
                algorithms=frozenset({"ES256"}),
                expected_issuer=ISSUER,
            ),
            StaticKeySet.from_jwks(jwks or self.components.signer.jwks()),
            self.clock,
        )


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock(float(NOW))


@pytest.fixture
def make_tts(tmp_path: Path, keys: dict[str, TestKey], clock: FrozenClock) -> Callable[..., Tts]:
    def _make(mutate: Mutator | None = None) -> Tts:
        config = copy.deepcopy(base_config(tmp_path, keys))
        if mutate is not None:
            mutate(config)
        settings = parse_settings(config, base_dir=tmp_path)
        sink = MemorySink()
        components = build_components(settings, clock=clock, sink=sink)
        assert isinstance(components.log, InMemoryIssuanceLog)
        return Tts(
            clock=clock,
            settings=settings,
            components=components,
            app=create_app(components),
            sink=sink,
            log=components.log,
            keys=keys,
        )

    return _make


@pytest.fixture
def tts(make_tts: Callable[..., Tts]) -> Tts:
    return make_tts()


@pytest.fixture
def config(tmp_path: Path, keys: dict[str, TestKey]) -> dict[str, object]:
    return base_config(tmp_path, keys)
