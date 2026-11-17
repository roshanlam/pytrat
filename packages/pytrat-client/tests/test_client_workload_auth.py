from __future__ import annotations

import httpx
import pytest

from pytrat.client import TransactionClient, WorkloadJwtAuth, bind_transaction
from pytrat.core import (
    AuthorizationError,
    ConfigurationError,
    InboundRequest,
    ReasonCode,
    WorkloadIdentity,
    WorkloadJwtAuthenticator,
    WorkloadKeys,
)
from pytrat.core.clock import FrozenClock
from pytrat.core.crypto import private_key_to_pem
from pytrat.core.testing import TokenFactory, generate_test_key


@pytest.fixture
def key_file(tmp_path):
    key = generate_test_key("ES256", kid="payment-1")
    path = tmp_path / "workload.pem"
    path.write_bytes(private_key_to_pem(key.private_key))
    path.chmod(0o600)
    return key, path


def make_auth(path, clock, **overrides) -> WorkloadJwtAuth:
    options = {
        "workload_id": "payment-service",
        "private_key_path": path,
        "kid": "payment-1",
        "alg": "ES256",
        "audiences": {"https://ledger.internal": "ledger-service"},
        "clock": clock,
        **overrides,
    }
    return WorkloadJwtAuth(**options)


def test_round_trip_with_resource_side_authenticator(key_file) -> None:
    key, path = key_file
    clock = FrozenClock()
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200)

    factory = TokenFactory.create()
    client = TransactionClient(
        ["https://ledger.internal"],
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        auth=make_auth(path, clock),
    )
    with bind_transaction(factory.verifier().verify(factory.mint())):
        client.post("https://ledger.internal/entries")
    inbound = InboundRequest(tuple(seen[0].headers.multi_items()))
    keys = WorkloadKeys({"payment-service": key.key_set()})
    identity = WorkloadJwtAuthenticator(keys, audience="ledger-service", clock=clock).authenticate(
        inbound
    )
    assert identity == WorkloadIdentity("payment-service", "workload-jwt")
    assert seen[0].headers["Workload-Identity"] != seen[0].headers["Txn-Token"]


def test_destination_without_audience_is_refused(key_file) -> None:
    _, path = key_file
    flow = make_auth(path, FrozenClock()).auth_flow(
        httpx.Request("GET", "https://other.internal/x")
    )
    with pytest.raises(AuthorizationError) as excinfo:
        next(flow)
    assert excinfo.value.reason is ReasonCode.DESTINATION_NOT_TRUSTED


def test_each_request_gets_a_fresh_jwt(key_file) -> None:
    _, path = key_file
    auth = make_auth(path, FrozenClock())
    first = next(auth.auth_flow(httpx.Request("GET", "https://ledger.internal/a")))
    second = next(auth.auth_flow(httpx.Request("GET", "https://ledger.internal/a")))
    assert first.headers["Workload-Identity"] != second.headers["Workload-Identity"]
    assert "payment-1" in repr(auth)


@pytest.mark.parametrize(
    "overrides",
    [
        {"workload_id": ""},
        {"lifetime": 0},
        {"lifetime": 301},
        {"alg": "PS256"},
        {"audiences": {}},
        {"audiences": {"http://ledger.internal": "x"}},
    ],
)
def test_invalid_configuration(key_file, overrides) -> None:
    _, path = key_file
    with pytest.raises(ConfigurationError):
        make_auth(path, FrozenClock(), **overrides)
