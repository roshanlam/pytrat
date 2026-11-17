"""Remote JWKS refresh (PyTraT profile P2), run against both shells."""

from __future__ import annotations

import asyncio
import json
from datetime import timedelta

import httpx
import pytest

from _client_testkit import JWKS_URL, Recorder
from pytrat.client import (
    AsyncJwksRefresher,
    JwksRefresher,
    RefreshingKeyProvider,
    parse_jwks,
)
from pytrat.client.jwks import MAX_JWKS_BYTES
from pytrat.core import (
    ConfigurationError,
    DependencyError,
    ReasonCode,
    TokenError,
    TokenVerifier,
    VerifierSettings,
)
from pytrat.core.testing import FrozenClock, TokenFactory, generate_test_key

TTL = timedelta(minutes=5)
MAX_STALE = timedelta(minutes=30)
MIN_INTERVAL = timedelta(seconds=30)


def jwks_response(*keys) -> httpx.Response:
    return httpx.Response(200, json={"keys": [k.jwk() for k in keys]})


class KeyServer:
    """A mutable JWKS endpoint for rotation scenarios."""

    def __init__(self, *keys) -> None:
        self.keys = list(keys)
        self.fail = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if self.fail:
            return httpx.Response(503)
        return jwks_response(*self.keys)


def _verifier(refresher, factory: TokenFactory) -> TokenVerifier:
    settings = VerifierSettings(trust_domain=factory.trust_domain, algorithms=frozenset({"ES256"}))
    return TokenVerifier(settings, refresher.keys, clock=factory.clock)


# ----------------------------------------------------------------------------- pure parts


def test_parse_jwks_builds_an_immutable_key_set() -> None:
    key = generate_test_key()
    keys = parse_jwks(json.dumps({"keys": [key.jwk()]}).encode())
    assert keys.kids == frozenset({key.kid})


@pytest.mark.parametrize(
    "data",
    [
        b'{"keys": []}',
        b"not json",
        b'{"keys": [{"kty": "oct", "k": "c2VjcmV0", "kid": "x"}]}',
        b" " * (MAX_JWKS_BYTES + 1),
    ],
)
def test_parse_jwks_rejects_bad_documents(data: bytes) -> None:
    with pytest.raises(ConfigurationError) as excinfo:
        parse_jwks(data)
    assert excinfo.value.reason is ReasonCode.KEY_UNKNOWN


def test_refreshing_provider_fails_closed_when_empty_or_stale() -> None:
    clock = FrozenClock()
    key = generate_test_key()
    provider = RefreshingKeyProvider(clock, timedelta(seconds=100))
    assert provider.get(key.kid) is None
    assert provider.age() is None
    assert "kids=[]" in repr(provider)
    provider.install(key.key_set())
    assert provider.get(key.kid) is not None
    assert key.kid in repr(provider)
    clock.advance(100)
    assert provider.get(key.kid) is not None
    clock.advance(1)
    assert provider.get(key.kid) is None
    with pytest.raises(ConfigurationError):
        RefreshingKeyProvider(clock, timedelta(0))


# ----------------------------------------------------------------------------- shells


async def test_initial_refresh_loads_keys(jwks_shell, clock) -> None:
    key = generate_test_key()
    recorder = Recorder(KeyServer(key))
    shell = jwks_shell(recorder, clock)
    assert await shell.refresh() is True
    assert shell.refresher.keys.get(key.kid) is not None
    sent = recorder.requests[0]
    assert str(sent.url) == JWKS_URL
    assert sent.method == "GET"


async def test_ttl_controls_refetching(jwks_shell, clock) -> None:
    recorder = Recorder(KeyServer(generate_test_key()))
    shell = jwks_shell(recorder, clock, ttl=TTL, min_refresh_interval=MIN_INTERVAL)
    await shell.refresh()
    clock.advance(TTL.total_seconds() - 1)
    assert await shell.refresh() is False
    assert recorder.calls == 1
    clock.advance(1)
    assert await shell.refresh() is True
    assert recorder.calls == 2


async def test_failed_refresh_keeps_last_good_set_until_max_stale(jwks_shell, clock) -> None:
    key = generate_test_key()
    server = KeyServer(key)
    shell = jwks_shell(Recorder(server), clock, ttl=TTL, max_stale=MAX_STALE)
    await shell.refresh()
    server.fail = True
    clock.advance(TTL.total_seconds())
    assert await shell.refresh() is False
    assert shell.refresher.keys.get(key.kid) is not None
    clock.advance(MAX_STALE.total_seconds())
    with pytest.raises(DependencyError) as excinfo:
        await shell.refresh()
    assert excinfo.value.reason is ReasonCode.DEPENDENCY_UNAVAILABLE
    assert shell.refresher.keys.get(key.kid) is None


@pytest.mark.parametrize(
    "respond",
    [
        lambda _: httpx.Response(500),
        lambda _: httpx.Response(302, headers={"location": "https://evil.example/jwks"}),
        lambda _: httpx.Response(200, content=b"x" * (MAX_JWKS_BYTES + 10)),
        lambda _: httpx.Response(200, json={"keys": [{"kty": "oct", "k": "AA", "kid": "h"}]}),
        lambda r: (_ for _ in ()).throw(httpx.ConnectError("down", request=r)),
    ],
    ids=["500", "redirect", "oversized", "symmetric-key", "network"],
)
async def test_failure_without_any_good_set_fails_closed(jwks_shell, clock, respond) -> None:
    recorder = Recorder(respond)
    shell = jwks_shell(recorder, clock)
    with pytest.raises(DependencyError):
        await shell.refresh()
    assert recorder.calls == 1
    assert shell.refresher.keys.get(None) is None


async def test_unknown_kid_storm_cannot_hammer_the_tts(jwks_shell, factory, clock) -> None:
    recorder = Recorder(KeyServer(factory.key))
    shell = jwks_shell(recorder, clock, min_refresh_interval=MIN_INTERVAL)
    verifier = _verifier(shell.refresher, factory)
    await shell.refresh()
    for i in range(50):
        with pytest.raises(TokenError) as excinfo:
            await shell.verify(verifier, factory.mint(headers={"kid": f"unknown-{i}"}))
        assert excinfo.value.reason is ReasonCode.KEY_UNKNOWN
    assert recorder.calls == 1  # every forced refresh is inside the minimum interval
    clock.advance(MIN_INTERVAL.total_seconds())
    with pytest.raises(TokenError):
        await shell.verify(verifier, factory.mint(headers={"kid": "unknown-x"}))
    assert recorder.calls == 2


async def test_rotated_key_is_picked_up_on_unknown_kid(jwks_shell, factory, clock) -> None:
    old_key = factory.key
    new_key = generate_test_key("ES256")
    server = KeyServer(old_key)
    recorder = Recorder(server)
    shell = jwks_shell(recorder, clock, min_refresh_interval=MIN_INTERVAL)
    verifier = _verifier(shell.refresher, factory)
    await shell.refresh()
    clock.advance(MIN_INTERVAL.total_seconds())
    server.keys = [old_key, new_key]
    token = await shell.verify(verifier, factory.mint(key=new_key))
    assert token.kid == new_key.kid
    assert recorder.calls == 2


async def test_unloaded_provider_triggers_refresh_on_first_verify(
    jwks_shell, factory, clock
) -> None:
    recorder = Recorder(KeyServer(factory.key))
    shell = jwks_shell(recorder, clock)
    verifier = _verifier(shell.refresher, factory)
    token = await shell.verify(verifier, factory.mint())
    assert token.kid == factory.key.kid


async def test_non_key_errors_do_not_trigger_refresh(jwks_shell, factory, clock) -> None:
    recorder = Recorder(KeyServer(factory.key))
    shell = jwks_shell(recorder, clock)
    verifier = _verifier(shell.refresher, factory)
    await shell.refresh()
    with pytest.raises(TokenError) as excinfo:
        await shell.verify(verifier, factory.mint(aud="other.internal"))
    assert excinfo.value.reason is ReasonCode.TRUST_DOMAIN_MISMATCH
    assert recorder.calls == 1


async def test_refresh_with_no_reachable_jwks_on_unknown_kid_is_dependency_error(
    jwks_shell, factory, clock
) -> None:
    shell = jwks_shell(Recorder(lambda _: httpx.Response(503)), clock)
    verifier = _verifier(shell.refresher, factory)
    with pytest.raises(DependencyError):
        await shell.verify(verifier, factory.mint())


# ----------------------------------------------------------------------------- single-flight


class _ConcurrentFetchLock:
    """A lock whose acquisition simulates another caller completing a fetch while we waited."""

    def __init__(self, refresher, key) -> None:
        self.refresher = refresher
        self.key = key

    def _other_caller_fetched(self) -> None:
        self.refresher._begin()
        self.refresher.keys.install(self.key.key_set())
        self.refresher._end()

    def __enter__(self) -> None:
        self._other_caller_fetched()

    def __exit__(self, *exc: object) -> None:
        return None

    async def __aenter__(self) -> None:
        self._other_caller_fetched()

    async def __aexit__(self, *exc: object) -> None:
        return None


async def test_waiter_reuses_concurrent_fetch_instead_of_refetching(jwks_shell, clock) -> None:
    key = generate_test_key()
    recorder = Recorder(KeyServer(key))
    shell = jwks_shell(recorder, clock, min_refresh_interval=timedelta(microseconds=1))
    shell.refresher._lock = _ConcurrentFetchLock(shell.refresher, key)
    assert await shell.refresh(force=True) is True  # the other caller's set is now in place
    assert recorder.calls == 0


async def test_async_refresh_is_single_flight(factory, clock) -> None:
    started = asyncio.Event()
    release = asyncio.Event()
    calls = 0

    async def slow(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        started.set()
        await release.wait()
        clock.advance(3600)  # far past min interval: only the generation check prevents a refetch
        return jwks_response(factory.key)

    refresher = AsyncJwksRefresher(
        JWKS_URL,
        clock=clock,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(slow)),
        max_stale=timedelta(days=1),
    )
    tasks = [asyncio.create_task(refresher.refresh(force=True)) for _ in range(10)]
    await started.wait()
    release.set()
    await asyncio.gather(*tasks)
    assert calls == 1


# ----------------------------------------------------------------------------- configuration

REFRESHERS = [JwksRefresher, AsyncJwksRefresher]


@pytest.mark.parametrize("cls", REFRESHERS)
@pytest.mark.parametrize(
    "kwargs",
    [
        {"jwks_url": "http://tts.internal/jwks"},
        {"jwks_url": "http://localhost/jwks"},
        {"ttl": timedelta(0)},
        {"ttl": timedelta(minutes=10), "max_stale": timedelta(minutes=5)},
        {"min_refresh_interval": timedelta(0)},
        {"timeout": 0},
    ],
)
def test_unsafe_refresher_configuration_is_refused(cls, kwargs) -> None:
    kwargs = dict(kwargs)
    url = kwargs.pop("jwks_url", JWKS_URL)
    with pytest.raises(ConfigurationError):
        cls(url, **kwargs)


@pytest.mark.parametrize("cls", REFRESHERS)
def test_localhost_jwks_allowed_with_flag(cls) -> None:
    refresher = cls("http://127.0.0.1:9000/jwks", allow_insecure_localhost=True)
    assert "127.0.0.1" in repr(refresher)


def test_sync_refresher_closes_only_what_it_owns() -> None:
    with JwksRefresher(JWKS_URL) as owned:
        pass
    assert owned._http.is_closed
    injected = httpx.Client()
    with JwksRefresher(JWKS_URL, http_client=injected):
        pass
    assert not injected.is_closed
    injected.close()


async def test_async_refresher_closes_only_what_it_owns() -> None:
    async with AsyncJwksRefresher(JWKS_URL) as owned:
        pass
    assert owned._http.is_closed
    injected = httpx.AsyncClient()
    async with AsyncJwksRefresher(JWKS_URL, http_client=injected):
        pass
    assert not injected.is_closed
    await injected.aclose()
