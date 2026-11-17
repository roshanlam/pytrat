"""Failure injection: real components wired together, one dependency broken at a time (M9).

Every scenario proves the same property: when the TTS, its JWKS, the Agent Attribute Store, an
audit sink or a replay store fails, the outcome is *deny* (no token, no handler call), with a
specific error, and the system recovers once the dependency does. Faults are injected in-process
(an httpx transport wrapping the real ASGI apps, failing store/sink doubles); nothing sleeps and
nothing touches the network.
"""

import dataclasses
import json
import os
import re
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Annotated

import httpx
import pytest
from fastapi import Depends, FastAPI

from pytrat.agents import AgentLimits, AgentRecord
from pytrat.client import (
    AsyncJwksRefresher,
    AsyncTransactionTokenClient,
    ExchangeError,
    PrivateKeyJwtCredential,
)
from pytrat.core import (
    AuditEvent,
    DependencyError,
    EventType,
    MemorySink,
    ReasonCode,
    SecretToken,
    StaticKeySet,
    TokenError,
    TokenVerifier,
    VerifiedToken,
    VerifierSettings,
)
from pytrat.core.constants import TOKEN_TYPE_ACCESS_TOKEN
from pytrat.core.crypto import private_key_to_pem, sign_compact
from pytrat.core.testing import FrozenClock, TestKey, TokenFactory, generate_test_key
from pytrat.fastapi import PyTraT, Transaction
from pytrat.server import (
    AgentProfile,
    InMemoryIssuanceLog,
    TtsComponents,
    WorkloadRegistry,
    build_components,
    create_app,
    parse_settings,
)
from pytrat.server.workloads import PrivateKeyJwtAuthenticator

pytestmark = pytest.mark.integration

TRUST_DOMAIN = "payments.internal"
TTS_ISSUER = "https://tts.payments.internal"
TOKEN_ENDPOINT = f"{TTS_ISSUER}/token"
JWKS_URL = f"{TTS_ISSUER}/.well-known/jwks.json"
IDP = "https://idp.example"
API = "https://api.payments.example"
NOW = 1_795_000_000
COMPACT_JWS = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}")

# --------------------------------------------------------------------------- fault doubles


type Fault = Callable[[httpx.Request], httpx.Response]


class FaultyTransport(httpx.AsyncBaseTransport):
    """Routes to a real ASGI app unless a fault is set; a fault may return or raise."""

    def __init__(self, app: FastAPI) -> None:
        self._app = httpx.ASGITransport(app=app)
        self.fault: Fault | None = None
        self.requests = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        if self.fault is not None:
            return self.fault(request)
        return await self._app.handle_async_request(request)


class LostResponseTransport(FaultyTransport):
    """The TTS processes the request, then the connection drops before the response arrives."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await super().handle_async_request(request)
        await response.aread()
        raise httpx.ReadError("connection reset by peer", request=request)


def refused(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("connection refused", request=request)


def timed_out(request: httpx.Request) -> httpx.Response:
    raise httpx.ReadTimeout("read timed out", request=request)


def status(code: int, body: bytes = b"", content_type: str = "text/html") -> Fault:
    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(code, content=body, headers={"Content-Type": content_type})

    return respond


def json_body(document: object, code: int = 200) -> Fault:
    return status(code, json.dumps(document).encode(), "application/json")


class FlakyAgentStore:
    """An Agent Attribute Store that can be taken down (as DependencyError or as a crash)."""

    def __init__(self, records: tuple[AgentRecord, ...] = ()) -> None:
        self._records = {record.id: record for record in records}
        self.failure: Exception | None = None

    def _check(self) -> None:
        if self.failure is not None:
            raise self.failure

    def get(self, agent_id: str) -> AgentRecord | None:
        self._check()
        return self._records.get(agent_id)

    def by_client_id(self, client_id: str) -> AgentRecord | None:
        self._check()
        return next((r for r in self._records.values() if r.client_id == client_id), None)


class FlakySink(MemorySink):
    """Records events until broken, then raises from ``emit`` (violating the sink contract)."""

    def __init__(self) -> None:
        super().__init__()
        self.broken = False

    def emit(self, event: AuditEvent) -> None:
        if self.broken:
            raise OSError("audit volume is full")
        super().emit(event)


class UnavailableReplayStore:
    """A replay store whose backend is down."""

    def __init__(self) -> None:
        self.calls = 0

    def record_once(self, key: str, expires_at: float) -> None:
        self.calls += 1
        raise DependencyError("replay store is unreachable")


# --------------------------------------------------------------------------- the deployment


def _secret(path: Path, data: bytes) -> Path:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    return path


@dataclass
class World:
    """A TTS, two exchange clients and the TTS-side doubles, sharing one frozen clock."""

    clock: FrozenClock
    idp: TestKey
    tts_key: TestKey
    components: TtsComponents
    gateway_pem: Path
    payment_pem: Path
    sink: FlakySink
    store: FlakyAgentStore
    transports: list[FaultyTransport] = field(default_factory=list)
    clients: list[AsyncTransactionTokenClient] = field(default_factory=list)

    @property
    def tts_jwks(self) -> StaticKeySet:
        return StaticKeySet.from_jwks(self.components.signer.jwks())

    def verifier(self) -> TokenVerifier:
        settings = VerifierSettings(trust_domain=TRUST_DOMAIN, expected_issuer=TTS_ISSUER)
        return TokenVerifier(settings, self.tts_jwks, self.clock)

    def app(self, **replacements: object) -> FastAPI:
        """The TTS app, with components optionally swapped for failing doubles."""
        return create_app(dataclasses.replace(self.components, **replacements))  # type: ignore[arg-type]

    def client(
        self,
        workload: str = "api-gateway",
        *,
        app: FastAPI | None = None,
        transport_type: type[FaultyTransport] = FaultyTransport,
    ) -> tuple[AsyncTransactionTokenClient, FaultyTransport]:
        pem, kid = (
            (self.gateway_pem, "gw-1") if workload == "api-gateway" else (self.payment_pem, "pay-1")
        )
        transport = transport_type(app or self.app())
        credential = PrivateKeyJwtCredential(
            workload, pem, alg="ES256", kid=kid, token_endpoint=TOKEN_ENDPOINT, clock=self.clock
        )
        client = AsyncTransactionTokenClient(
            TOKEN_ENDPOINT,
            credential,
            self.verifier(),
            http_client=httpx.AsyncClient(transport=transport),
        )
        self.transports.append(transport)
        self.clients.append(client)
        return client, transport

    def access_token(self, **overrides: object) -> SecretToken:
        now = int(self.clock.now())
        claims = {
            "iss": IDP,
            "aud": API,
            "sub": "user:123",
            "scope": "payments.transfer",
            "iat": now,
            "exp": now + 600,
            "client_id": "web-app",
            **overrides,
        }
        return SecretToken(
            sign_compact(claims, self.idp.private_key, alg="ES256", kid=self.idp.kid, typ="at+jwt")
        )

    async def issue(
        self, client: AsyncTransactionTokenClient, scope: str = "payments.transfer"
    ) -> VerifiedToken:
        return await client.issue(
            audience=TRUST_DOMAIN,
            scope=scope,
            subject_token=self.access_token(),
            subject_token_type=TOKEN_TYPE_ACCESS_TOKEN,
            request_details={"amount_minor": 10000},
        )

    def denials(self) -> list[AuditEvent]:
        denied = {EventType.ISSUANCE_DENIED, EventType.REPLACEMENT_DENIED}
        return [event for event in self.sink.events if event.event_type in denied]


@pytest.fixture
async def world(tmp_path: Path) -> AsyncIterator[World]:
    clock = FrozenClock(NOW)
    tts_key, idp = generate_test_key("ES256", kid="tts-1"), generate_test_key("ES256", kid="idp-1")
    gateway_key, payment_key = (
        generate_test_key("ES256", kid="gw-1"),
        generate_test_key("ES256", kid="pay-1"),
    )
    _secret(tmp_path / "tts.pem", private_key_to_pem(tts_key.private_key))
    (tmp_path / "idp.json").write_text(json.dumps({"keys": [idp.jwk()]}))
    settings = parse_settings(
        {
            "trust_domain": TRUST_DOMAIN,
            "issuer": TTS_ISSUER,
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
                        "tctx": {"amount_minor": "integer"},
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
    sink, store = FlakySink(), FlakyAgentStore()
    components = build_components(settings, clock=clock, sink=sink)
    components = dataclasses.replace(
        components, agent_profile=AgentProfile(store=store, limits=AgentLimits(max_hops=3))
    )
    world = World(
        clock=clock,
        idp=idp,
        tts_key=tts_key,
        components=components,
        gateway_pem=_secret(tmp_path / "gw.pem", private_key_to_pem(gateway_key.private_key)),
        payment_pem=_secret(tmp_path / "pay.pem", private_key_to_pem(payment_key.private_key)),
        sink=sink,
        store=store,
    )
    yield world
    for client in world.clients:
        await client.aclose()


def assert_no_token_in(error: BaseException) -> None:
    assert not COMPACT_JWS.search(str(error))
    assert not COMPACT_JWS.search(repr(error))


# --------------------------------------------------------------------------- TTS down (client view)


@pytest.mark.parametrize(
    ("fault", "error_type", "reason", "status_code"),
    [
        pytest.param(
            refused, DependencyError, ReasonCode.DEPENDENCY_UNAVAILABLE, None, id="refused"
        ),
        pytest.param(
            timed_out, DependencyError, ReasonCode.DEPENDENCY_UNAVAILABLE, None, id="timeout"
        ),
        pytest.param(status(502), ExchangeError, ReasonCode.EXCHANGE_FAILED, 502, id="502-html"),
        pytest.param(
            json_body({"error": "temporarily_unavailable"}, 503),
            ExchangeError,
            ReasonCode.EXCHANGE_FAILED,
            503,
            id="503-oauth",
        ),
        pytest.param(
            status(500, b"Internal Server Error", "text/plain"),
            ExchangeError,
            ReasonCode.EXCHANGE_FAILED,
            500,
            id="500-text",
        ),
        pytest.param(
            status(200, b'{"access_token": "abc"', "application/json"),
            ExchangeError,
            ReasonCode.EXCHANGE_FAILED,
            200,
            id="truncated-json",
        ),
        pytest.param(
            status(200, b"<html>maintenance</html>"),
            ExchangeError,
            ReasonCode.EXCHANGE_FAILED,
            200,
            id="html-200",
        ),
        pytest.param(
            json_body([1, 2, 3]), ExchangeError, ReasonCode.EXCHANGE_FAILED, 200, id="json-array"
        ),
        pytest.param(
            status(200, b"x" * 2_000_000, "application/json"),
            ExchangeError,
            ReasonCode.EXCHANGE_FAILED,
            None,
            id="oversized",
        ),
        pytest.param(
            status(307, b"", "text/html"),
            ExchangeError,
            ReasonCode.EXCHANGE_FAILED,
            307,
            id="redirect",
        ),
    ],
)
async def test_tts_failure_yields_specific_error_and_no_token(
    world: World,
    fault: Fault,
    error_type: type[Exception],
    reason: ReasonCode,
    status_code: int | None,
) -> None:
    client, transport = world.client()
    transport.fault = fault
    with pytest.raises(error_type) as excinfo:
        await world.issue(client)
    assert excinfo.value.reason is reason  # type: ignore[attr-defined]
    if isinstance(excinfo.value, ExchangeError):
        assert excinfo.value.status_code == status_code
    assert_no_token_in(excinfo.value)
    # The fault clears: the same client recovers without any poisoned state.
    transport.fault = None
    assert (await world.issue(client)).claims.aud == TRUST_DOMAIN


async def test_tts_response_with_a_forged_token_is_rejected(world: World) -> None:
    """A man-in-the-middle (or a confused TTS) answers 200 with a token the client cannot trust."""
    impostor = TokenFactory(key=generate_test_key("ES256", kid="tts-1"), clock=world.clock)
    client, transport = world.client()
    for forged in (impostor.mint(iss=TTS_ISSUER), impostor.mint(headers={"kid": "tts-9"})):
        transport.fault = json_body(
            {
                "access_token": forged,
                "issued_token_type": "urn:ietf:params:oauth:token-type:txn_token",
                "token_type": "N_A",
                "expires_in": 60,
            }
        )
        with pytest.raises(TokenError) as excinfo:
            await world.issue(client)
        assert excinfo.value.reason in {ReasonCode.SIGNATURE_INVALID, ReasonCode.KEY_UNKNOWN}
        assert_no_token_in(excinfo.value)


async def test_response_lost_after_issuance_releases_no_token(world: World) -> None:
    """The TTS signed and recorded a token, but the reply never arrived: nothing is usable."""
    client, _ = world.client(transport_type=LostResponseTransport)
    with pytest.raises(DependencyError) as excinfo:
        await world.issue(client)
    assert excinfo.value.reason is ReasonCode.DEPENDENCY_UNAVAILABLE
    issued = [e for e in world.sink.events if e.event_type is EventType.TOKEN_ISSUED]
    assert len(issued) == 1  # the TTS log still accounts for the token it signed


# --------------------------------------------------------------------------- JWKS down (resource)


@dataclass
class Ledger:
    """A resource service that trusts the TTS's published JWKS through a refresher."""

    http: httpx.AsyncClient
    jwks_transport: FaultyTransport
    refresher: AsyncJwksRefresher
    calls: list[str]
    sink: MemorySink

    async def transfer(self, token: str) -> httpx.Response:
        return await self.http.post("/internal/transfer", headers={"Txn-Token": token})


MAX_STALE = timedelta(minutes=5)


@pytest.fixture
async def ledger(world: World) -> AsyncIterator[Ledger]:
    jwks_transport = FaultyTransport(world.app())
    refresher = AsyncJwksRefresher(
        JWKS_URL,
        clock=world.clock,
        ttl=timedelta(minutes=1),
        max_stale=MAX_STALE,
        min_refresh_interval=timedelta(seconds=1),
        http_client=httpx.AsyncClient(transport=jwks_transport),
    )
    verifier = TokenVerifier(
        VerifierSettings(trust_domain=TRUST_DOMAIN, expected_issuer=TTS_ISSUER),
        refresher.keys,
        world.clock,
    )
    sink = MemorySink()
    pytrat = PyTraT(service="ledger", verifier=verifier, audit=sink, jwks_refresher=refresher)
    app = FastAPI(lifespan=pytrat.lifespan)
    pytrat.install(app)
    calls: list[str] = []
    requirement = pytrat.require_transaction(
        scope="payments.transfer", require_workload_identity=False
    )

    @app.post("/internal/transfer")
    async def transfer(txn: Annotated[Transaction, Depends(requirement)]) -> dict[str, str]:
        calls.append(txn.id)
        return {"status": "posted"}

    await refresher.refresh()
    async with (
        pytrat.lifespan(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://ledger.internal"
        ) as http,
    ):
        yield Ledger(http, jwks_transport, refresher, calls, sink)
    await refresher.aclose()


def reason_of(response: httpx.Response) -> str:
    return str(response.json()["reason_code"])


BAD_JWKS = [
    pytest.param(refused, id="refused"),
    pytest.param(timed_out, id="timeout"),
    pytest.param(status(503), id="503"),
    pytest.param(status(200, b"{not json", "application/json"), id="garbage"),
    pytest.param(json_body({"keys": []}), id="empty-set"),
    pytest.param(json_body({"keys": [{"kty": "oct", "kid": "tts-1", "k": "c2VjcmV0"}]}), id="oct"),
    # Under the 256 KiB cap but nested deeper than the decoder's stack: before strict_loads
    # mapped RecursionError to ValueError, this escaped the refresher as a 500.
    pytest.param(status(200, b"[" * 120_000 + b"]" * 120_000, "application/json"), id="deep"),
    pytest.param(status(200, b" " * 300_000, "application/json"), id="oversized"),
]


@pytest.mark.parametrize("fault", BAD_JWKS)
async def test_known_keys_keep_working_within_max_stale_while_jwks_is_down(
    world: World, ledger: Ledger, fault: Fault
) -> None:
    client, _ = world.client()
    ledger.jwks_transport.fault = fault
    world.clock.advance(MAX_STALE.total_seconds() - 1)  # TTL long gone, max_stale not yet
    token = await world.issue(client)
    response = await ledger.transfer(token.forwardable.reveal())
    assert response.status_code == 200
    assert ledger.jwks_transport.requests >= 2  # the refresh was attempted, and failed


@pytest.mark.parametrize("fault", BAD_JWKS)
async def test_keys_older_than_max_stale_fail_closed(
    world: World, ledger: Ledger, fault: Fault
) -> None:
    client, _ = world.client()
    ledger.jwks_transport.fault = fault
    world.clock.advance(MAX_STALE.total_seconds() + 1)
    token = await world.issue(client)  # a fresh, genuine token
    response = await ledger.transfer(token.forwardable.reveal())
    assert response.status_code == 401
    assert reason_of(response) == ReasonCode.KEY_UNKNOWN
    assert ledger.calls == []
    with pytest.raises(DependencyError):
        await ledger.refresher.refresh(force=True)
    # Recovery: once the JWKS endpoint answers again, the same token is accepted.
    ledger.jwks_transport.fault = None
    world.clock.advance(1)
    assert (await ledger.transfer(token.forwardable.reveal())).status_code == 200


async def test_unknown_kid_during_jwks_outage_is_denied(world: World, ledger: Ledger) -> None:
    """A token under a kid the ledger never saw (a rotation, or a forgery) needs a fresh JWKS."""
    rotated = TokenFactory(
        key=generate_test_key("ES256", kid="tts-2"), trust_domain=TRUST_DOMAIN, clock=world.clock
    )
    ledger.jwks_transport.fault = refused
    response = await ledger.transfer(rotated.mint(iss=TTS_ISSUER))
    assert response.status_code == 401
    assert reason_of(response) == ReasonCode.KEY_UNKNOWN
    assert ledger.calls == []


async def test_poisoned_jwks_refresh_is_discarded_whole(world: World, ledger: Ledger) -> None:
    """A refreshed set mixing a new key with an invalid one installs nothing: old keys only."""
    client, _ = world.client()
    rotated = generate_test_key("ES256", kid="tts-2")
    poisoned = {
        "keys": [world.tts_key.jwk(), rotated.jwk(), {**rotated.jwk(), "kid": "x", "d": "AA"}]
    }
    ledger.jwks_transport.fault = json_body(poisoned)
    world.clock.advance(61)
    forged = TokenFactory(key=rotated, trust_domain=TRUST_DOMAIN, clock=world.clock)
    denied = await ledger.transfer(forged.mint(iss=TTS_ISSUER))
    assert (denied.status_code, reason_of(denied)) == (401, ReasonCode.KEY_UNKNOWN)
    genuine = await world.issue(client)
    assert (await ledger.transfer(genuine.forwardable.reveal())).status_code == 200
    assert ledger.calls == [genuine.id]


# --------------------------------------------------------------------------- AAS down (TTS)


@pytest.mark.parametrize(
    ("failure", "status_code", "oauth_error"),
    [
        (DependencyError("agent store unreachable"), 503, "temporarily_unavailable"),
        (RuntimeError("driver crashed"), 500, "server_error"),
    ],
)
async def test_agent_store_down_during_issuance_denies(
    world: World, failure: Exception, status_code: int, oauth_error: str
) -> None:
    client, _ = world.client()
    world.store.failure = failure
    with pytest.raises(ExchangeError) as excinfo:
        await world.issue(client)
    assert (excinfo.value.status_code, excinfo.value.oauth_error) == (status_code, oauth_error)
    [denial] = world.denials()
    assert denial.event_type is EventType.ISSUANCE_DENIED
    assert denial.reason_code is ReasonCode.DEPENDENCY_UNAVAILABLE
    world.store.failure = None
    assert (await world.issue(client)).claims.agentic_ctx is None


@pytest.mark.parametrize(
    ("failure", "status_code"),
    [(DependencyError("agent store unreachable"), 503), (RuntimeError("driver crashed"), 500)],
)
async def test_agent_store_down_during_replacement_denies(
    world: World, failure: Exception, status_code: int
) -> None:
    gateway, _ = world.client()
    payment, _ = world.client("payment-service")
    current = await world.issue(gateway)
    world.store.failure = failure
    with pytest.raises(ExchangeError) as excinfo:
        await payment.replace(current)
    assert excinfo.value.status_code == status_code
    [denial] = world.denials()
    assert denial.event_type is EventType.REPLACEMENT_DENIED
    assert denial.reason_code is ReasonCode.DEPENDENCY_UNAVAILABLE
    assert denial.transaction_id == current.claims.txn


# --------------------------------------------------------------------------- audit sink down


async def test_tts_sink_failure_on_denial_keeps_the_original_denial(world: World) -> None:
    """AuditRecorder.record_denial never raises: a broken sink cannot change a refusal."""
    client, _ = world.client()
    world.sink.broken = True
    with pytest.raises(ExchangeError) as excinfo:
        await world.issue(client, scope="payments.admin")
    assert (excinfo.value.status_code, excinfo.value.oauth_error) == (400, "invalid_scope")
    # The authoritative issuance log still recorded the denial.
    log = world.components.log
    assert isinstance(log, InMemoryIssuanceLog)
    assert [record.event_type for record in log.records] == [EventType.ISSUANCE_DENIED.value]


async def test_tts_sink_failure_on_success_releases_no_token(world: World) -> None:
    client, _ = world.client()
    world.sink.broken = True
    with pytest.raises(ExchangeError) as excinfo:
        await world.issue(client)
    assert (excinfo.value.status_code, excinfo.value.oauth_error) == (500, "server_error")
    world.sink.broken = False
    assert (await world.issue(client)).claims.aud == TRUST_DOMAIN


@pytest.fixture
def resource_kit() -> TokenFactory:
    return TokenFactory.create(trust_domain=TRUST_DOMAIN)


def resource_app(
    factory: TokenFactory, sink: FlakySink, **options: object
) -> tuple[FastAPI, PyTraT, list[str]]:
    pytrat = PyTraT(service="ledger", verifier=factory.verifier(), audit=sink, **options)  # type: ignore[arg-type]
    app = FastAPI(lifespan=pytrat.lifespan)
    pytrat.install(app)
    calls: list[str] = []
    requirement = pytrat.require_transaction(
        scope="payments.transfer",
        require_workload_identity=False,
        single_use="replay_store" in options,
    )

    @app.post("/internal/transfer")
    async def transfer(txn: Annotated[Transaction, Depends(requirement)]) -> dict[str, str]:
        calls.append(txn.id)
        return {"status": "posted"}

    return app, pytrat, calls


async def call(app: FastAPI, pytrat: PyTraT, token: str) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with (
        pytrat.lifespan(app),
        httpx.AsyncClient(transport=transport, base_url="http://ledger.internal") as http,
    ):
        return await http.post("/internal/transfer", headers={"Txn-Token": token})


@pytest.mark.parametrize(
    ("claims", "status", "reason"),
    [
        pytest.param({}, 503, ReasonCode.DEPENDENCY_UNAVAILABLE, id="would-be-granted"),
        pytest.param(
            {"scope": "payments.read"}, 403, ReasonCode.SCOPE_INSUFFICIENT, id="scope-denied"
        ),
        pytest.param(
            {"aud": "other.domain"}, 401, ReasonCode.TRUST_DOMAIN_MISMATCH, id="token-rejected"
        ),
    ],
)
async def test_resource_sink_failure_never_turns_into_an_allow(
    resource_kit: TokenFactory, claims: dict[str, object], status: int, reason: ReasonCode
) -> None:
    """A broken sink keeps a denial's own reason; an unaudited grant is refused with 503."""
    sink = FlakySink()
    sink.broken = True
    app, pytrat, calls = resource_app(resource_kit, sink)
    response = await call(app, pytrat, resource_kit.mint(**claims))
    assert response.status_code == status
    assert reason_of(response) == reason
    assert calls == []


# --------------------------------------------------------------------------- replay store down


async def test_resource_replay_store_down_denies_with_503(resource_kit: TokenFactory) -> None:
    store = UnavailableReplayStore()
    app, pytrat, calls = resource_app(resource_kit, FlakySink(), replay_store=store)
    response = await call(app, pytrat, resource_kit.mint())
    assert response.status_code == 503
    assert reason_of(response) == ReasonCode.DEPENDENCY_UNAVAILABLE
    assert store.calls == 1
    assert calls == []


async def test_tts_assertion_replay_store_down_denies(world: World) -> None:
    store = UnavailableReplayStore()
    authenticator = PrivateKeyJwtAuthenticator(
        WorkloadRegistry.from_settings(world.components.settings),
        token_endpoint=TOKEN_ENDPOINT,
        algorithms=frozenset({"ES256"}),
        replay_store=store,
        clock=world.clock,
    )
    client, _ = world.client(app=world.app(authenticator=authenticator))
    with pytest.raises(ExchangeError) as excinfo:
        await world.issue(client)
    assert (excinfo.value.status_code, excinfo.value.oauth_error) == (
        503,
        "temporarily_unavailable",
    )
    [denial] = world.denials()
    assert denial.reason_code is ReasonCode.DEPENDENCY_UNAVAILABLE
    assert store.calls == 1
