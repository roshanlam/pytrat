from __future__ import annotations

import pytest

from pytrat.core import (
    AuthenticationError,
    AuthorizationError,
    EventType,
    InboundRequest,
    MemorySink,
    PyTraTError,
    ReasonCode,
    TokenError,
    WorkloadIdentity,
)
from pytrat.core.testing import TokenFactory
from pytrat.policy import CompiledPolicy, TransactionEnforcer

BODY = {"amount_minor": 10000, "currency": "USD"}


class StaticCaller:
    def __init__(self, caller: str | None, *, invalid: bool = False) -> None:
        self.caller = caller
        self.invalid = invalid

    def authenticate(self, request: InboundRequest) -> WorkloadIdentity | None:
        if self.invalid:
            raise AuthenticationError(ReasonCode.WORKLOAD_UNAUTHENTICATED, "bad credential")
        return WorkloadIdentity(self.caller, "test") if self.caller else None


@pytest.fixture
def factory() -> TokenFactory:
    return TokenFactory.create()


@pytest.fixture
def policy() -> CompiledPolicy:
    return CompiledPolicy.build(
        policy_id="transfer",
        allowed_scopes=["payments.transfer"],
        allowed_callers=["payment-service"],
        bind_context=["amount_minor", "currency"],
    )


def enforcer(factory: TokenFactory, sink: MemorySink, caller=None) -> TransactionEnforcer:
    return TransactionEnforcer(
        service="ledger",
        verify=factory.verifier(),
        authenticator=caller or StaticCaller("payment-service"),
        audit=sink,
    )


def headers(token: str | None = None, *extra: tuple[str, str]) -> InboundRequest:
    pairs = ((("Txn-Token", token),) if token else ()) + extra
    return InboundRequest(pairs)


def denied(fn, error_type=PyTraTError) -> PyTraTError:
    with pytest.raises(error_type) as excinfo:
        fn()
    return excinfo.value


def test_allowed_request_returns_transaction_and_audits(factory, policy) -> None:
    sink = MemorySink()
    raw = factory.mint(txn="txn-1", tctx=BODY)
    txn = enforcer(factory, sink).enforce(policy, headers(raw), BODY)
    assert txn is not None
    assert (txn.id, txn.subject, str(txn.scope)) == ("txn-1", "user:123", "payments.transfer")
    assert txn.tctx == BODY
    assert txn.claims.req_wl == "api-gateway"
    assert txn.caller == WorkloadIdentity("payment-service", "test")
    [event] = sink.events
    assert event.event_type is EventType.AUTHORIZATION_GRANTED
    assert event.caller_workload == "payment-service"
    assert event.detail == {"bound_fields": "amount_minor,currency"}
    assert event.token_digest == txn.token.digest


def test_missing_token(factory, policy) -> None:
    sink = MemorySink()
    error = denied(lambda: enforcer(factory, sink).enforce(policy, headers(), BODY), TokenError)
    assert error.reason is ReasonCode.TOKEN_MISSING
    assert sink.events[0].event_type is EventType.TOKEN_REJECTED


def test_two_tokens_are_rejected(factory, policy) -> None:
    """txn-tokens-11 §12.1: the header MUST carry exactly one Txn-Token."""
    raw = factory.mint(tctx=BODY)
    request = headers(raw, ("txn-token", raw))
    error = denied(
        lambda: enforcer(factory, MemorySink()).enforce(policy, request, BODY), TokenError
    )
    assert error.reason is ReasonCode.TOKEN_MALFORMED


def test_invalid_token_is_audited_without_claims(factory, policy) -> None:
    sink = MemorySink()
    raw = factory.mint(aud="elsewhere")
    error = denied(lambda: enforcer(factory, sink).enforce(policy, headers(raw), BODY), TokenError)
    assert error.reason is ReasonCode.TRUST_DOMAIN_MISMATCH
    [event] = sink.events
    assert event.event_type is EventType.TOKEN_REJECTED
    assert event.transaction_id is None
    assert event.reason_code is ReasonCode.TRUST_DOMAIN_MISMATCH


def test_tampered_body_is_denied_and_audited_with_field_not_value(factory, policy) -> None:
    sink = MemorySink()
    raw = factory.mint(txn="txn-9274", tctx=BODY)
    tampered = {**BODY, "amount_minor": 900000}
    error = denied(
        lambda: enforcer(factory, sink).enforce(policy, headers(raw), tampered), AuthorizationError
    )
    assert error.reason is ReasonCode.TRANSACTION_CONTEXT_MISMATCH
    [event] = sink.events
    assert event.event_type is EventType.AUTHORIZATION_DENIED
    assert event.transaction_id == "txn-9274"
    assert event.policy_id == "transfer"
    assert "amount_minor" in event.detail["check"]
    assert "900000" not in event.to_json()


def test_invalid_workload_credential(factory, policy) -> None:
    sink = MemorySink()
    raw = factory.mint(tctx=BODY)
    caller = StaticCaller(None, invalid=True)
    error = denied(
        lambda: enforcer(factory, sink, caller).enforce(policy, headers(raw), BODY),
        AuthenticationError,
    )
    assert error.reason is ReasonCode.WORKLOAD_UNAUTHENTICATED
    assert sink.events[0].event_type is EventType.AUTHORIZATION_DENIED


def test_no_authenticator_means_no_caller_and_denies_identity_policies(factory, policy) -> None:
    raw = factory.mint(tctx=BODY)
    plain = TransactionEnforcer(service="ledger", verify=factory.verifier().verify)
    error = denied(lambda: plain.enforce(policy, headers(raw), BODY), AuthenticationError)
    assert error.reason is ReasonCode.WORKLOAD_UNAUTHENTICATED


def test_wrong_caller(factory, policy) -> None:
    raw = factory.mint(tctx=BODY)
    sneaky = enforcer(factory, MemorySink(), StaticCaller("api-gateway"))
    error = denied(lambda: sneaky.enforce(policy, headers(raw), BODY), AuthorizationError)
    assert error.reason is ReasonCode.CALLER_NOT_ALLOWED


def test_transactionless_policy_ignores_token(factory) -> None:
    sink = MemorySink()
    health = CompiledPolicy.build(policy_id="health", require_transaction=False)
    assert enforcer(factory, sink).enforce(health, headers(), {}) is None
    assert sink.events[0].event_type is EventType.AUTHORIZATION_GRANTED


def test_derived_transforms_are_audited(factory) -> None:
    from pytrat.core import Derived

    sink = MemorySink()
    to_minor = Derived("amount_major", "amount_minor", lambda v: v * 100, "major-to-minor")  # type: ignore[operator]
    policy = CompiledPolicy.build(
        policy_id="transfer",
        allowed_scopes=["payments.transfer"],
        bind_context=[to_minor],
    )
    raw = factory.mint(tctx=BODY)
    service = enforcer(factory, sink)
    assert service.service == "ledger"
    service.enforce(policy, headers(raw), {"amount_major": 100})
    assert sink.events[0].detail["transforms"] == "major-to-minor"


def test_denials_after_verification_carry_transaction_id(factory, policy) -> None:
    raw = factory.mint(txn="txn-42", tctx=BODY)
    error = denied(
        lambda: enforcer(factory, MemorySink()).enforce(policy, headers(raw), {}),
        AuthorizationError,
    )
    assert error.transaction_id == "txn-42"


def test_token_failures_never_carry_transaction_id(factory, policy) -> None:
    raw = factory.mint(txn="txn-42", aud="elsewhere")
    error = denied(
        lambda: enforcer(factory, MemorySink()).enforce(policy, headers(raw), BODY), TokenError
    )
    assert error.transaction_id is None
