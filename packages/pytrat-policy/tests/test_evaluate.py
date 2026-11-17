from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import pytest

from pytrat.core import (
    AuthenticationError,
    AuthorizationError,
    DependencyError,
    FrozenClock,
    InMemoryReplayStore,
    PyTraTError,
    ReasonCode,
    TokenError,
    VerifiedToken,
)
from pytrat.policy import (
    AgentRequirements,
    AuthorizationRequest,
    CompiledPolicy,
    Decision,
    PolicyEvaluator,
)

type Mint = Callable[..., VerifiedToken]

BODY = {
    "source_account": "account-A",
    "destination_account": "account-B",
    "amount_minor": 10000,
    "currency": "USD",
}


def agentic_ctx(
    *,
    hops: int = 1,
    assurance: str | None = "high",
    originator: str = "planner",
    proximate: str = "executor",
) -> dict[str, object]:
    chain: dict[str, object] = {"hop_count": hops}
    if assurance is not None:
        chain["min_assurance_level"] = assurance
    return {
        "originator": {"id": originator, "session_id": "s-1"},
        "proximate_agent": {"id": proximate},
        "chain_metadata": chain,
    }


FIELDS = ["source_account", "destination_account", "amount_minor", "currency"]


def transfer_policy(**overrides: object) -> CompiledPolicy:
    arguments: dict[str, object] = {
        "policy_id": "transfer",
        "allowed_scopes": ["payments.transfer"],
        "bind_context": FIELDS,
        "allowed_callers": ["payment-service"],
    }
    arguments.update(overrides)
    return CompiledPolicy.build(**arguments)  # type: ignore[arg-type]


def request(
    token: object, caller: str | None = "payment-service", data: object = None
) -> AuthorizationRequest:
    return AuthorizationRequest(
        token=token,  # type: ignore[arg-type]
        caller=caller,
        request_data=BODY if data is None else data,  # type: ignore[arg-type]
    )


def assert_denied(
    policy: CompiledPolicy, req: AuthorizationRequest, reason: ReasonCode
) -> PyTraTError:
    decision = policy.evaluate(req)
    assert decision == Decision(allowed=False, reason=reason, policy_id=policy.policy_id)
    with pytest.raises(PyTraTError) as info:
        policy.enforce(req)
    assert info.value.reason is reason
    return info.value


class Directory:
    def __init__(self, *registered: str) -> None:
        self.registered = set(registered)
        self.calls: list[str] = []

    def is_registered(self, agent_id: str) -> bool:
        self.calls.append(agent_id)
        return agent_id in self.registered


# ------------------------------------------------------------------ allow


def test_valid_request_is_allowed_with_binding_result(mint: Mint) -> None:
    policy = transfer_policy()
    decision = policy.evaluate(request(mint()))
    assert decision.allowed
    assert decision.reason is None
    assert decision.policy_id == "transfer"
    assert decision.binding is not None
    assert decision.binding.checked == tuple(FIELDS)
    assert policy.enforce(request(mint())).allowed


def test_compiled_policy_satisfies_policy_evaluator_protocol() -> None:
    evaluator: PolicyEvaluator = transfer_policy()
    assert evaluator.evaluate is not None


def test_any_one_allowed_scope_suffices(mint: Mint) -> None:
    policy = transfer_policy(allowed_scopes="ledger.post payments.transfer")
    assert policy.evaluate(request(mint(scope="payments.transfer other"))).allowed


def test_any_authenticated_caller_allowed_when_callers_omitted(mint: Mint) -> None:
    policy = transfer_policy(allowed_callers=None)
    assert policy.evaluate(request(mint(), caller="anyone")).allowed


def test_workload_identity_not_required_allows_anonymous_caller(mint: Mint) -> None:
    policy = transfer_policy(allowed_callers=None, require_workload_identity=False)
    assert policy.evaluate(request(mint(), caller=None)).allowed


def test_transactionless_policy_checks_only_the_caller(mint: Mint) -> None:
    policy = CompiledPolicy.build(policy_id="health", require_transaction=False)
    decision = policy.evaluate(request(None))
    assert decision == Decision(allowed=True, reason=None, policy_id="health")
    assert_denied(policy, request(None, caller=None), ReasonCode.WORKLOAD_UNAUTHENTICATED)


# ------------------------------------------------------------------ deny, one per check


def test_missing_token_is_denied_token_missing() -> None:
    error = assert_denied(transfer_policy(), request(None), ReasonCode.TOKEN_MISSING)
    assert isinstance(error, TokenError)


def test_widened_scope_request_is_denied_scope_insufficient(mint: Mint) -> None:
    assert_denied(
        transfer_policy(), request(mint(scope="payments.read")), ReasonCode.SCOPE_INSUFFICIENT
    )


@pytest.mark.parametrize("caller", [None, ""])
def test_unauthenticated_caller_is_denied(mint: Mint, caller: str | None) -> None:
    error = assert_denied(
        transfer_policy(), request(mint(), caller=caller), ReasonCode.WORKLOAD_UNAUTHENTICATED
    )
    assert isinstance(error, AuthenticationError)
    assert error.http_status == 401


def test_unlisted_caller_is_denied_caller_not_allowed(mint: Mint) -> None:
    error = assert_denied(
        transfer_policy(), request(mint(), caller="api-gateway"), ReasonCode.CALLER_NOT_ALLOWED
    )
    assert isinstance(error, AuthorizationError)


def test_tampered_amount_is_denied_context_mismatch(mint: Mint) -> None:
    data = {**BODY, "amount_minor": 99999}
    assert_denied(
        transfer_policy(), request(mint(), data=data), ReasonCode.TRANSACTION_CONTEXT_MISMATCH
    )


def test_token_without_tctx_is_denied_context_missing(mint: Mint) -> None:
    assert_denied(
        transfer_policy(), request(mint(tctx=None)), ReasonCode.TRANSACTION_CONTEXT_MISSING
    )


def test_float_in_tctx_is_denied_claim_invalid(mint: Mint) -> None:
    token = mint(tctx={**BODY, "amount_minor": 100.0})
    assert_denied(transfer_policy(), request(token), ReasonCode.CLAIM_INVALID)


# ------------------------------------------------------------------ evaluation order


def test_scope_failure_wins_over_binding_failure(mint: Mint) -> None:
    token = mint(scope="payments.read")
    data = {**BODY, "amount_minor": 1}
    assert_denied(transfer_policy(), request(token, data=data), ReasonCode.SCOPE_INSUFFICIENT)


def test_token_missing_wins_over_caller_failure() -> None:
    assert_denied(transfer_policy(), request(None, caller=None), ReasonCode.TOKEN_MISSING)


def test_scope_failure_wins_over_caller_failure(mint: Mint) -> None:
    assert_denied(
        transfer_policy(),
        request(mint(scope="other"), caller="intruder"),
        ReasonCode.SCOPE_INSUFFICIENT,
    )


def test_caller_failure_wins_over_binding_failure(mint: Mint) -> None:
    assert_denied(
        transfer_policy(),
        request(mint(), caller="intruder", data={}),
        ReasonCode.CALLER_NOT_ALLOWED,
    )


def test_binding_failure_wins_over_agent_failure(mint: Mint) -> None:
    policy = transfer_policy(agents=AgentRequirements(enabled=True, maximum_hops=1))
    token = mint(agentic_ctx=agentic_ctx(hops=5))
    assert_denied(policy, request(token, data={}), ReasonCode.TRANSACTION_CONTEXT_MISMATCH)


def test_agent_failure_wins_over_replay_and_does_not_consume_use(mint: Mint) -> None:
    store = InMemoryReplayStore(clock=FrozenClock())
    policy = transfer_policy(
        single_use=True,
        replay_store=store,
        agents=AgentRequirements(enabled=True, maximum_hops=1),
    )
    assert_denied(
        policy, request(mint(agentic_ctx=agentic_ctx(hops=2))), ReasonCode.AGENT_HOP_LIMIT_EXCEEDED
    )
    assert len(store) == 0


# ------------------------------------------------------------------ agents


AGENTS = AgentRequirements(
    enabled=True,
    maximum_hops=3,
    minimum_assurance="medium",
    require_chain_replacement=True,
    allowed_originators=frozenset({"planner"}),
)


def test_agent_request_within_constraints_is_allowed(mint: Mint) -> None:
    policy = transfer_policy(agents=AGENTS)
    token = mint(agentic_ctx=agentic_ctx(hops=3, assurance="medium"))
    assert policy.evaluate(request(token)).allowed


def test_agent_hop_limit_exceeded(mint: Mint) -> None:
    token = mint(agentic_ctx=agentic_ctx(hops=4))
    assert_denied(
        transfer_policy(agents=AGENTS), request(token), ReasonCode.AGENT_HOP_LIMIT_EXCEEDED
    )


@pytest.mark.parametrize("assurance", ["low", "unverified", None, "made-up"])
def test_agent_assurance_insufficient(mint: Mint, assurance: str | None) -> None:
    token = mint(agentic_ctx=agentic_ctx(assurance=assurance))
    assert_denied(
        transfer_policy(agents=AGENTS), request(token), ReasonCode.AGENT_ASSURANCE_INSUFFICIENT
    )


def test_unlisted_originator_is_denied_agent_not_allowed(mint: Mint) -> None:
    token = mint(agentic_ctx=agentic_ctx(originator="rogue"))
    assert_denied(transfer_policy(agents=AGENTS), request(token), ReasonCode.AGENT_NOT_ALLOWED)


@pytest.mark.parametrize(
    "requirements",
    [
        AgentRequirements(enabled=True, minimum_assurance="high"),
        AgentRequirements(enabled=True, allowed_originators=frozenset({"trusted-agent"})),
        AGENTS,
    ],
)
def test_agent_constraints_cannot_be_bypassed_by_omitting_agent_context(
    mint: Mint, requirements: AgentRequirements
) -> None:
    """Security review #2: a plain token must not satisfy assurance or originator constraints."""
    assert_denied(
        transfer_policy(agents=requirements), request(mint()), ReasonCode.AGENT_CONTEXT_MISSING
    )


def test_hop_limit_alone_accepts_tokens_without_agents(mint: Mint) -> None:
    policy = transfer_policy(agents=AgentRequirements(enabled=True, maximum_hops=2))
    assert policy.evaluate(request(mint())).allowed


def test_missing_agent_context_denied_when_required(mint: Mint) -> None:
    required = AgentRequirements(enabled=True, require_agent_context=True)
    assert_denied(
        transfer_policy(agents=required), request(mint()), ReasonCode.AGENT_CONTEXT_MISSING
    )


def test_agent_context_not_rejected_when_agents_disabled(mint: Mint) -> None:
    token = mint(agentic_ctx=agentic_ctx(hops=50, assurance=None, originator="anyone"))
    assert transfer_policy().evaluate(request(token)).allowed


def test_session_id_is_not_an_authorization_input(mint: Mint) -> None:
    ctx = agentic_ctx()
    ctx["originator"] = {"id": "planner", "session_id": "attacker-chosen"}
    assert transfer_policy(agents=AGENTS).evaluate(request(mint(agentic_ctx=ctx))).allowed


def test_verified_agents_are_allowed(mint: Mint) -> None:
    directory = Directory("planner", "executor")
    policy = transfer_policy(
        agents=AgentRequirements(enabled=True, require_verified_agent=True),
        agent_directory=directory,
    )
    assert policy.evaluate(request(mint(agentic_ctx=agentic_ctx()))).allowed
    assert directory.calls == ["planner", "executor"]


def test_verified_agent_requirement_denies_tokens_without_agent_context(mint: Mint) -> None:
    policy = transfer_policy(
        agents=AgentRequirements(enabled=True, require_verified_agent=True),
        agent_directory=Directory("planner", "executor"),
    )
    assert_denied(policy, request(mint()), ReasonCode.AGENT_CONTEXT_MISSING)


@pytest.mark.parametrize("registered", [("planner",), ("executor",), ()])
def test_unregistered_agent_is_denied_agent_unverified(
    mint: Mint, registered: tuple[str, ...]
) -> None:
    policy = transfer_policy(
        agents=AgentRequirements(enabled=True, require_verified_agent=True),
        agent_directory=Directory(*registered),
    )
    assert_denied(policy, request(mint(agentic_ctx=agentic_ctx())), ReasonCode.AGENT_UNVERIFIED)


def test_directory_returning_truthy_non_bool_is_denied(mint: Mint) -> None:
    @dataclass
    class Sloppy:
        def is_registered(self, agent_id: str) -> bool:
            return "yes"  # type: ignore[return-value]

    policy = transfer_policy(
        agents=AgentRequirements(enabled=True, require_verified_agent=True),
        agent_directory=Sloppy(),
    )
    assert_denied(policy, request(mint(agentic_ctx=agentic_ctx())), ReasonCode.AGENT_UNVERIFIED)


def test_directory_outage_is_denied_dependency_unavailable(mint: Mint) -> None:
    class Down:
        def is_registered(self, agent_id: str) -> bool:
            raise DependencyError("directory unreachable")

    policy = transfer_policy(
        agents=AgentRequirements(enabled=True, require_verified_agent=True),
        agent_directory=Down(),
    )
    assert_denied(
        policy, request(mint(agentic_ctx=agentic_ctx())), ReasonCode.DEPENDENCY_UNAVAILABLE
    )


def test_unexpected_exception_propagates_from_evaluate(mint: Mint) -> None:
    class Broken:
        def is_registered(self, agent_id: str) -> bool:
            raise RuntimeError("bug")

    policy = transfer_policy(
        agents=AgentRequirements(enabled=True, require_verified_agent=True),
        agent_directory=Broken(),
    )
    with pytest.raises(RuntimeError):
        policy.evaluate(request(mint(agentic_ctx=agentic_ctx())))


def test_dependencies_removed_after_construction_fail_closed(mint: Mint) -> None:
    # Defence in depth: construction rejects these, but the request path must not assume it.
    policy = transfer_policy(
        single_use=True,
        replay_store=InMemoryReplayStore(),
        agents=AgentRequirements(enabled=True, require_verified_agent=True),
        agent_directory=Directory("planner", "executor"),
    )
    object.__setattr__(policy, "agent_directory", None)
    assert_denied(
        policy, request(mint(agentic_ctx=agentic_ctx())), ReasonCode.DEPENDENCY_UNAVAILABLE
    )
    object.__setattr__(policy, "replay_store", None)
    object.__setattr__(policy, "agents", AgentRequirements())
    assert_denied(policy, request(mint()), ReasonCode.DEPENDENCY_UNAVAILABLE)


def test_scope_check_fails_closed_without_allowed_scopes(mint: Mint) -> None:
    policy = transfer_policy()
    object.__setattr__(policy, "allowed_scopes", None)
    assert_denied(policy, request(mint()), ReasonCode.SCOPE_INSUFFICIENT)


# ------------------------------------------------------------------ replay


def test_replayed_single_use_token_is_denied_replay_detected(factory: object, mint: Mint) -> None:
    store = InMemoryReplayStore(clock=FrozenClock())
    policy = transfer_policy(single_use=True, replay_store=store)
    token = mint()
    assert policy.evaluate(request(token)).allowed
    assert_denied(policy, request(token), ReasonCode.REPLAY_DETECTED)


def test_replay_is_per_policy(mint: Mint) -> None:
    store = InMemoryReplayStore(clock=FrozenClock())
    first = transfer_policy(single_use=True, replay_store=store)
    second = transfer_policy(policy_id="other", single_use=True, replay_store=store)
    token = mint()
    assert first.evaluate(request(token)).allowed
    assert second.evaluate(request(token)).allowed


def test_reusable_token_is_allowed_without_single_use(mint: Mint) -> None:
    policy = transfer_policy()
    token = mint()
    assert policy.evaluate(request(token)).allowed
    assert policy.evaluate(request(token)).allowed


# ------------------------------------------------------------------ value types


def test_decision_allowed_and_reason_are_consistent() -> None:
    with pytest.raises(ValueError, match="exactly when"):
        Decision(allowed=True, reason=ReasonCode.TOKEN_MISSING, policy_id="p")
    with pytest.raises(ValueError, match="exactly when"):
        Decision(allowed=False, reason=None, policy_id="p")


def test_authorization_request_defaults_to_empty_data() -> None:
    req = AuthorizationRequest(token=None, caller=None)
    assert dict(req.request_data) == {}
    assert req.operation is None
