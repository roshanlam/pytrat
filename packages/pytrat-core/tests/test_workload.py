from __future__ import annotations

import pytest

from pytrat.core import (
    AuthenticationError,
    ConfigurationError,
    FirstMatchAuthenticator,
    InboundRequest,
    ReasonCode,
    TokenError,
    TrustedProxyHeaderAuthenticator,
    WorkloadIdentity,
    WorkloadJwtAuthenticator,
)
from pytrat.core.clock import FrozenClock
from pytrat.core.crypto import sign_compact
from pytrat.core.testing import TestKey, generate_test_key

AUDIENCE = "ledger-service"


@pytest.fixture
def clock() -> FrozenClock:
    return FrozenClock(1_795_000_000)


@pytest.fixture
def key() -> TestKey:
    return generate_test_key("ES256", kid="payment-service-1")


def workload_jwt(
    key: TestKey, clock: FrozenClock, typ: str = "wit+jwt", **overrides: object
) -> str:
    now = int(clock.now())
    claims: dict[str, object] = {
        "sub": "payment-service",
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + 60,
    }
    for name, value in overrides.items():
        if value is None:
            claims.pop(name)
        else:
            claims[name] = value
    return sign_compact(claims, key.private_key, alg=key.alg, kid=key.kid, typ=typ)


def authenticator(key: TestKey, clock: FrozenClock) -> WorkloadJwtAuthenticator:
    return WorkloadJwtAuthenticator(key.key_set(), audience=AUDIENCE, clock=clock)


def unauthenticated(auth, request: InboundRequest) -> None:
    with pytest.raises(AuthenticationError) as excinfo:
        auth.authenticate(request)
    assert excinfo.value.reason is ReasonCode.WORKLOAD_UNAUTHENTICATED
    assert excinfo.value.http_status == 401


class TestInboundRequest:
    def test_case_insensitive_and_duplicates(self) -> None:
        request = InboundRequest((("X-A", "1"), ("x-a", "2"), ("B", "3")))
        assert request.values("x-A") == ["1", "2"]
        assert request.single("b") == "3"
        assert request.single("missing") is None
        with pytest.raises(TokenError):
            request.single("x-a")
        assert InboundRequest.from_mapping({"A": "1"}, peer="10.0.0.1").peer == "10.0.0.1"


class TestWorkloadJwt:
    @pytest.mark.parametrize("typ", ["wit+jwt", "JWT"])
    def test_valid(self, key, clock, typ: str) -> None:
        request = InboundRequest.from_mapping({"Workload-Identity": workload_jwt(key, clock, typ)})
        assert authenticator(key, clock).authenticate(request) == WorkloadIdentity(
            "payment-service", "workload-jwt"
        )

    def test_audience_list(self, key, clock) -> None:
        token = workload_jwt(key, clock, aud=["other", AUDIENCE])
        assert authenticator(key, clock).authenticate(
            InboundRequest.from_mapping({"Workload-Identity": token})
        )

    def test_absent_header_is_not_an_error(self, key, clock) -> None:
        assert authenticator(key, clock).authenticate(InboundRequest(())) is None

    @pytest.mark.parametrize(
        "overrides",
        [
            {"sub": None},
            {"sub": ""},
            {"aud": "payments-service"},
            {"aud": None},
            {"iat": None},
            {"exp": "soon"},
            {"iat": True},
            {"exp": 1_795_000_000},
            {"exp": 1_795_000_000 + 3600},
            {"iat": 1_795_000_000 + 30, "exp": 1_795_000_000 + 90},
        ],
    )
    def test_invalid_claims(self, key, clock, overrides) -> None:
        token = workload_jwt(key, clock, **overrides)
        unauthenticated(
            authenticator(key, clock), InboundRequest.from_mapping({"Workload-Identity": token})
        )

    def test_expired(self, key, clock) -> None:
        token = workload_jwt(key, clock)
        clock.advance(120)
        unauthenticated(
            authenticator(key, clock), InboundRequest.from_mapping({"Workload-Identity": token})
        )

    def test_untrusted_signer(self, key, clock) -> None:
        attacker = generate_test_key("ES256", kid=key.kid)
        token = workload_jwt(attacker, clock)
        unauthenticated(
            authenticator(key, clock), InboundRequest.from_mapping({"Workload-Identity": token})
        )

    def test_txn_token_cannot_be_used_as_workload_credential(self, key, clock) -> None:
        """txn-tokens-11 §13.12: a Txn-Token is not an authentication credential."""
        token = workload_jwt(key, clock, typ="txntoken+jwt")
        unauthenticated(
            authenticator(key, clock), InboundRequest.from_mapping({"Workload-Identity": token})
        )

    def test_repeated_header(self, key, clock) -> None:
        token = workload_jwt(key, clock)
        request = InboundRequest((("Workload-Identity", token), ("workload-identity", token)))
        unauthenticated(authenticator(key, clock), request)

    def test_requires_audience(self, key) -> None:
        with pytest.raises(ConfigurationError):
            WorkloadJwtAuthenticator(key.key_set(), audience="")


class TestTrustedProxy:
    auth = TrustedProxyHeaderAuthenticator(
        header="X-Client-SPIFFE-ID", trusted_proxies=["10.0.0.0/8", "::1/128"]
    )

    def test_trusted_peer(self) -> None:
        request = InboundRequest.from_mapping(
            {"X-Client-SPIFFE-ID": "spiffe://td/payment"}, peer="10.1.2.3"
        )
        assert self.auth.authenticate(request) == WorkloadIdentity(
            "spiffe://td/payment", "mtls-proxy"
        )

    def test_absent(self) -> None:
        assert self.auth.authenticate(InboundRequest((), peer="10.1.2.3")) is None

    @pytest.mark.parametrize("peer", ["192.168.1.1", None, "not-an-ip"])
    def test_header_from_untrusted_peer_is_an_attack(self, peer: str | None) -> None:
        request = InboundRequest.from_mapping(
            {"X-Client-SPIFFE-ID": "spiffe://td/admin"}, peer=peer
        )
        unauthenticated(self.auth, request)

    @pytest.mark.parametrize(
        "headers",
        [(("X-Client-SPIFFE-ID", "a"), ("X-Client-SPIFFE-ID", "b")), (("X-Client-SPIFFE-ID", ""),)],
    )
    def test_malformed_header(self, headers) -> None:
        unauthenticated(self.auth, InboundRequest(headers, peer="10.0.0.1"))

    @pytest.mark.parametrize("cidrs", [[], ["not-a-cidr"]])
    def test_configuration(self, cidrs: list[str]) -> None:
        with pytest.raises(ConfigurationError):
            TrustedProxyHeaderAuthenticator(header="X", trusted_proxies=cidrs)


class TestFirstMatch:
    def test_order_and_errors(self, key, clock) -> None:
        proxy = TrustedProxyHeaderAuthenticator(header="X-Id", trusted_proxies=["10.0.0.0/8"])
        chain = FirstMatchAuthenticator(proxy, authenticator(key, clock))
        jwt_request = InboundRequest.from_mapping({"Workload-Identity": workload_jwt(key, clock)})
        assert chain.authenticate(jwt_request).method == "workload-jwt"  # type: ignore[union-attr]
        assert chain.authenticate(InboundRequest(())) is None
        unauthenticated(chain, InboundRequest.from_mapping({"X-Id": "spoofed"}, peer="8.8.8.8"))
        with pytest.raises(ConfigurationError):
            FirstMatchAuthenticator()
