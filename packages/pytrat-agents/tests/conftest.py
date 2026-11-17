from __future__ import annotations

from collections.abc import Callable, Mapping

import pytest

from pytrat.agents import AgentLimits, AgentRecord, AssuranceOrdering, InMemoryAgentStore
from pytrat.core import TransactionClaims, VerifiedToken, parse_claims
from pytrat.core.testing import TestKey, TokenFactory, generate_test_key

EXTERNAL = AgentRecord(
    id="3p-assistant-ext-99",
    name="External assistant",
    owner="partner",
    assurance_level="low",
    version="1.0",
    provenance="external",
    client_id="3p-client",
)
INTERNAL = AgentRecord(
    id="1p-billing-svc-v2",
    name="Billing agent",
    owner="payments-team",
    assurance_level="high",
    version="2.4.1",
    provenance="sha256:abc",
    attributes={"tee": "sgx"},
    client_id="billing-client",
)
MEDIUM = AgentRecord(
    id="1p-report-agent",
    name="Report agent",
    owner="reporting",
    assurance_level="medium",
    version="0.9",
    provenance="sha256:def",
)


def agentic_ctx(
    *,
    originator: str = EXTERNAL.id,
    proximate: str = EXTERNAL.id,
    hop_count: int = 1,
    min_assurance_level: str | None = "low",
    attr_store_ref: str | None = None,
    session_id: str | None = None,
) -> dict[str, object]:
    chain: dict[str, object] = {"hop_count": hop_count}
    if min_assurance_level is not None:
        chain["min_assurance_level"] = min_assurance_level
    ctx: dict[str, object] = {
        "originator": {"id": originator},
        "proximate_agent": {"id": proximate},
        "chain_metadata": chain,
    }
    if session_id is not None:
        ctx["originator"] = {"id": originator, "session_id": session_id}
        ctx["proximate_agent"] = {"id": proximate, "session_id": session_id}
    if attr_store_ref is not None:
        ctx["attr_store_ref"] = attr_store_ref
    return ctx


def make_claims(**overrides: object) -> TransactionClaims:
    payload: dict[str, object] = {
        "aud": "trust-domain.example",
        "txn": "txn-1",
        "sub": "user:alice",
        "scope": "billing.read billing.write",
        "req_wl": "apigateway",
        "iat": 1_000,
        "exp": 1_060,
        "act": {"sub": EXTERNAL.id},
        "agentic_ctx": agentic_ctx(),
    }
    for name, value in overrides.items():
        if value is None:
            payload.pop(name, None)
        else:
            payload[name] = value
    return parse_claims(payload)


@pytest.fixture
def external() -> AgentRecord:
    return EXTERNAL


@pytest.fixture
def internal() -> AgentRecord:
    return INTERNAL


@pytest.fixture
def medium() -> AgentRecord:
    return MEDIUM


@pytest.fixture
def ctx_payload() -> Callable[..., dict[str, object]]:
    return agentic_ctx


@pytest.fixture
def claims() -> Callable[..., TransactionClaims]:
    return make_claims


@pytest.fixture
def ordering() -> AssuranceOrdering:
    return AssuranceOrdering()


@pytest.fixture
def store() -> InMemoryAgentStore:
    return InMemoryAgentStore([EXTERNAL, INTERNAL, MEDIUM])


@pytest.fixture
def limits(ordering: AssuranceOrdering) -> AgentLimits:
    return AgentLimits(max_hops=5, ordering=ordering)


@pytest.fixture(scope="session")
def es256_key() -> TestKey:
    return generate_test_key("ES256", kid="agents-es256")


@pytest.fixture
def factory(es256_key: TestKey) -> TokenFactory:
    return TokenFactory(key=es256_key, trust_domain="trust-domain.example")


@pytest.fixture
def mint_verified(factory: TokenFactory) -> Callable[..., VerifiedToken]:
    verifier = factory.verifier()

    def mint(**overrides: object) -> VerifiedToken:
        defaults: Mapping[str, object] = {
            "scope": "billing.read",
            "act": {"sub": EXTERNAL.id},
            "agentic_ctx": agentic_ctx(proximate=INTERNAL.id, hop_count=2),
        }
        return verifier.verify(factory.mint(**{**defaults, **overrides}))

    return mint
