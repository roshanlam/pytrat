"""The ``pytrat_kit`` pytest plugin: what it mints passes the real verifiers, and nothing more."""

from __future__ import annotations

import time

import pytest

from pytrat.core import (
    TXN_TOKEN_HEADER,
    AuthenticationError,
    InboundRequest,
    ReasonCode,
    TokenError,
    TokenVerifier,
    VerifierSettings,
    WorkloadJwtAuthenticator,
)
from pytrat.core.testing.pytest_plugin import TransactionTestKit
from pytrat.core.workload import DEFAULT_WORKLOAD_JWT_HEADER

TRANSFER = {"amount_minor": 10000, "currency": "USD"}


def test_fixtures_are_registered_automatically(pytrat_kit: TransactionTestKit) -> None:
    assert pytrat_kit.trust_domain == "example.internal"


class TestTrustDomainOverride:
    @pytest.fixture
    def pytrat_trust_domain(self) -> str:
        return "payments.internal"

    def test_overriding_the_fixture_changes_the_audience(
        self, pytrat_kit: TransactionTestKit
    ) -> None:
        verified = pytrat_kit.verifier().verify(pytrat_kit.token(scope="payments.transfer"))
        assert verified.claims.aud == "payments.internal"


def test_token_passes_an_independently_configured_verifier(pytrat_kit: TransactionTestKit) -> None:
    verifier = TokenVerifier(
        VerifierSettings(trust_domain=pytrat_kit.trust_domain), pytrat_kit.tts_keys()
    )
    verified = verifier.verify(pytrat_kit.token(scope="payments.transfer", tctx=TRANSFER))
    assert str(verified.claims.scope) == "payments.transfer"
    assert verified.claims.tctx == TRANSFER
    assert verified.claims.rctx is None


def test_claims_can_be_overridden_and_removed(pytrat_kit: TransactionTestKit) -> None:
    verified = pytrat_kit.verifier().verify(pytrat_kit.token(scope="a", sub="user:42"))
    assert verified.claims.sub == "user:42"
    with pytest.raises(TokenError) as raised:
        pytrat_kit.verifier().verify(pytrat_kit.token(scope="a", txn=None))
    assert raised.value.reason is ReasonCode.CLAIM_MISSING


def test_token_for_another_trust_domain_is_rejected(pytrat_kit: TransactionTestKit) -> None:
    other = TransactionTestKit(trust_domain="elsewhere.internal")
    verifier = TokenVerifier(
        VerifierSettings(trust_domain="elsewhere.internal"), pytrat_kit.tts_keys()
    )
    with pytest.raises(TokenError) as raised:
        verifier.verify(pytrat_kit.token(scope="a"))
    assert raised.value.reason is ReasonCode.TRUST_DOMAIN_MISMATCH
    with pytest.raises(TokenError) as raised:  # each kit generates its own TTS key
        other.verifier().verify(pytrat_kit.token(scope="a"))
    assert raised.value.reason is ReasonCode.SIGNATURE_INVALID


def test_headers_authenticate_the_caller(pytrat_kit: TransactionTestKit) -> None:
    authenticator = WorkloadJwtAuthenticator(
        pytrat_kit.workload_keys("payment-service"), audience="ledger-service"
    )
    headers = pytrat_kit.headers(scope="a", caller="payment-service", audience="ledger-service")
    pytrat_kit.verifier().verify(headers[TXN_TOKEN_HEADER])
    identity = authenticator.authenticate(InboundRequest.from_mapping(headers))
    assert identity is not None
    assert identity.id == "payment-service"


def test_caller_cannot_impersonate_another_registered_workload(
    pytrat_kit: TransactionTestKit,
) -> None:
    authenticator = WorkloadJwtAuthenticator(
        pytrat_kit.workload_keys("payment-service"), audience="ledger-service"
    )
    headers = pytrat_kit.headers(scope="a", caller="attacker", audience="ledger-service")
    with pytest.raises(AuthenticationError) as raised:
        authenticator.authenticate(InboundRequest.from_mapping(headers))
    assert raised.value.reason is ReasonCode.WORKLOAD_UNAUTHENTICATED


def test_workload_jwt_for_another_service_is_rejected(pytrat_kit: TransactionTestKit) -> None:
    authenticator = WorkloadJwtAuthenticator(
        pytrat_kit.workload_keys("payment-service"), audience="ledger-service"
    )
    headers = pytrat_kit.headers(scope="a", caller="payment-service", audience="other-service")
    with pytest.raises(AuthenticationError) as raised:
        authenticator.authenticate(InboundRequest.from_mapping(headers))
    assert raised.value.reason is ReasonCode.WORKLOAD_UNAUTHENTICATED


def test_headers_without_caller_carry_no_workload_credential(
    pytrat_kit: TransactionTestKit,
) -> None:
    assert DEFAULT_WORKLOAD_JWT_HEADER not in pytrat_kit.headers(scope="a")


def test_caller_without_audience_is_a_usage_error(pytrat_kit: TransactionTestKit) -> None:
    with pytest.raises(ValueError, match="audience is required"):
        pytrat_kit.headers(scope="a", caller="payment-service")


def test_workload_keys_are_stable_within_a_kit(pytrat_kit: TransactionTestKit) -> None:
    first = pytrat_kit.workload_keys("payment-service")
    # Keys registered before a request are the ones its JWT is signed with.
    headers = pytrat_kit.headers(scope="a", caller="payment-service", audience="ledger-service")
    authenticator = WorkloadJwtAuthenticator(first, audience="ledger-service")
    assert authenticator.authenticate(InboundRequest.from_mapping(headers)) is not None


def test_repr_reveals_no_key_material(pytrat_kit: TransactionTestKit) -> None:
    assert repr(pytrat_kit) == "TransactionTestKit(trust_domain='example.internal')"


def test_expired_token_as_documented_in_the_testing_guide(pytrat_kit: TransactionTestKit) -> None:
    now = int(time.time())
    with pytest.raises(TokenError) as raised:
        pytrat_kit.verifier().verify(pytrat_kit.token(scope="a", iat=now - 180, exp=now - 120))
    assert raised.value.reason is ReasonCode.TOKEN_EXPIRED
