"""Tests for the small value types: scopes, claims, secrets, assurance and JSON helpers."""

from __future__ import annotations

import pickle
from typing import ClassVar

import pytest
from hypothesis import given
from hypothesis import strategies as st

from pytrat.core import (
    AgenticContext,
    AssuranceOrdering,
    AuthorizationError,
    ConfigurationError,
    ReasonCode,
    Scope,
    SecretToken,
    TokenError,
    parse_claims,
    token_digest,
)
from pytrat.core._json import (
    DuplicateKeyError,
    compact_dumps,
    freeze,
    freeze_object,
    strict_loads,
    thaw,
)
from pytrat.core.clock import FrozenClock, SystemClock

scope_tokens = st.text(
    alphabet=st.characters(
        codec="ascii", exclude_characters=' "\\', min_codepoint=0x21, max_codepoint=0x7E
    ),
    min_size=1,
    max_size=12,
)


class TestScope:
    def test_parse_and_canonical_form(self) -> None:
        scope = Scope.parse("payments.transfer accounts.read")
        assert str(scope) == "accounts.read payments.transfer"
        assert "payments.transfer" in scope
        assert len(scope) == 2
        assert list(scope) == ["accounts.read", "payments.transfer"]

    @pytest.mark.parametrize("raw", ["", " ", "a  b", " a", "a ", "a\tb", 'a"', "a\\b", "é"])
    def test_invalid_syntax(self, raw: str) -> None:
        with pytest.raises(TokenError) as excinfo:
            Scope.parse(raw)
        assert excinfo.value.reason is ReasonCode.CLAIM_INVALID

    def test_non_string(self) -> None:
        with pytest.raises(TokenError):
            Scope.parse(["a"])  # type: ignore[arg-type]

    def test_coerce_and_algebra(self) -> None:
        wide = Scope.coerce(["a", "b", "c"])
        narrow = Scope.coerce("a b")
        assert Scope.coerce(narrow) is narrow
        assert narrow.issubset(wide)
        assert not wide.issubset(narrow)
        assert narrow.intersection(Scope.of("b", "z")) == Scope.of("b")
        assert narrow.intersection(Scope.of("z")) is None

    @given(st.sets(scope_tokens, min_size=1, max_size=6))
    def test_round_trip(self, tokens: set[str]) -> None:
        scope = Scope(frozenset(tokens))
        assert Scope.parse(str(scope)) == scope

    @given(
        st.sets(scope_tokens, min_size=1, max_size=6), st.sets(scope_tokens, min_size=1, max_size=6)
    )
    def test_intersection_is_subset_of_both(self, a: set[str], b: set[str]) -> None:
        common = Scope(frozenset(a)).intersection(Scope(frozenset(b)))
        if common is not None:
            assert common.issubset(Scope(frozenset(a)))
            assert common.issubset(Scope(frozenset(b)))


class TestClaims:
    BASE: ClassVar[dict[str, object]] = {
        "aud": "d",
        "txn": "t",
        "sub": "s",
        "scope": "x",
        "req_wl": "gw,agent-svc",
        "iat": 1,
        "exp": 2,
    }

    def test_frozen_context_cannot_be_mutated(self) -> None:
        claims = parse_claims({**self.BASE, "tctx": {"a": [1, {"b": 2}]}})
        assert claims.tctx is not None
        with pytest.raises(TypeError):
            claims.tctx["a"] = 2  # type: ignore[index]
        assert claims.tctx["a"] == (1, {"b": 2})

    def test_aliases_and_payload_round_trip(self) -> None:
        claims = parse_claims({**self.BASE, "act": {"sub": "agent-1"}, "tctx": {"a": [1]}})
        assert claims.id == "t"
        assert claims.trust_domain == "d"
        assert claims.actor == "agent-1"
        assert claims.requesting_workloads == ("gw,agent-svc",)
        assert parse_claims(claims.to_payload()) == claims
        assert claims.to_payload()["tctx"] == {"a": [1]}

    def test_actor_absent_or_non_string(self) -> None:
        assert parse_claims(self.BASE).actor is None
        assert parse_claims({**self.BASE, "act": {"sub": 5}}).actor is None

    def test_agent_profile_splits_workload_chain(self) -> None:
        agentic = {
            "originator": {"id": "ext-agent", "session_id": "s1"},
            "proximate_agent": {"id": "int-agent"},
            "chain_metadata": {"hop_count": 2, "min_assurance_level": "low"},
            "unknown_member": True,
        }
        claims = parse_claims({**self.BASE, "agentic_ctx": agentic})
        assert claims.requesting_workloads == ("gw", "agent-svc")
        assert isinstance(claims.agentic_ctx, AgenticContext)
        assert claims.agentic_ctx.chain_metadata.hop_count == 2

    @pytest.mark.parametrize("hop_count", [0, -1, True, 1.0])
    def test_invalid_hop_count(self, hop_count: object) -> None:
        agentic = {
            "originator": {"id": "a"},
            "proximate_agent": {"id": "a"},
            "chain_metadata": {"hop_count": hop_count},
        }
        with pytest.raises(TokenError) as excinfo:
            parse_claims({**self.BASE, "agentic_ctx": agentic})
        assert excinfo.value.reason is ReasonCode.CLAIM_INVALID


class TestSecretToken:
    def test_value_hidden_everywhere(self) -> None:
        secret = SecretToken("eyJhbGc.payload.signature")
        for rendered in (repr(secret), str(secret), f"{secret}", f"{secret!r}"):
            assert "payload" not in rendered
            assert secret.digest[:12] in rendered
        assert secret.reveal() == "eyJhbGc.payload.signature"
        assert secret.digest == token_digest("eyJhbGc.payload.signature")

    def test_equality_and_hash(self) -> None:
        assert SecretToken("a") == SecretToken("a")
        assert SecretToken("a") != SecretToken("b")
        assert SecretToken("a") != "a"
        assert len({SecretToken("a"), SecretToken("a")}) == 1

    def test_rejects_empty_and_pickling(self) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            SecretToken("")
        with pytest.raises(TypeError):
            pickle.dumps(SecretToken("a"))


class TestAssurance:
    ordering = AssuranceOrdering()

    def test_minimum_treats_unknown_and_absent_as_lowest(self) -> None:
        assert self.ordering.lowest == "unverified"
        assert self.ordering.minimum("high", "low") == "low"
        assert self.ordering.minimum("high", None) == "unverified"
        assert self.ordering.minimum("high", "galactic") == "unverified"

    def test_satisfies(self) -> None:
        assert self.ordering.satisfies("high", "medium")
        assert self.ordering.satisfies("medium", "medium")
        assert not self.ordering.satisfies("low", "medium")

    @pytest.mark.parametrize("actual", [None, "galactic"])
    def test_unknown_actual_never_satisfies(self, actual: str | None) -> None:
        with pytest.raises(AuthorizationError) as excinfo:
            self.ordering.satisfies(actual, "low")
        assert excinfo.value.reason is ReasonCode.AGENT_ASSURANCE_INSUFFICIENT

    def test_unknown_requirement_is_a_configuration_error(self) -> None:
        with pytest.raises(ConfigurationError):
            self.ordering.satisfies("high", "galactic")
        assert self.ordering.require_known("low") == "low"
        assert self.ordering.is_known("low")

    @pytest.mark.parametrize("levels", [(), ("a", "a"), ("a", "")])
    def test_invalid_orderings(self, levels: tuple[str, ...]) -> None:
        with pytest.raises(ConfigurationError):
            AssuranceOrdering(levels)


class TestJson:
    def test_strict_loads(self) -> None:
        assert strict_loads('{"a": [1, 2]}') == {"a": [1, 2]}
        with pytest.raises(DuplicateKeyError):
            strict_loads('{"a": 1, "a": 2}')
        with pytest.raises(ValueError, match="Infinity"):
            strict_loads('{"a": Infinity}')

    def test_freeze_thaw(self) -> None:
        frozen = freeze({"a": [1, {"b": None}]})
        assert thaw(frozen) == {"a": [1, {"b": None}]}
        assert compact_dumps(frozen) == b'{"a":[1,{"b":null}]}'

    @pytest.mark.parametrize("value", [{1: "a"}, {"a": b"x"}, {"a": object()}])
    def test_freeze_rejects_non_json(self, value: object) -> None:
        with pytest.raises(TypeError):
            freeze(value)

    def test_freeze_object_requires_mapping(self) -> None:
        with pytest.raises(TypeError):
            freeze_object([1])


def test_clocks() -> None:
    clock = FrozenClock(100.0)
    clock.advance(5)
    assert clock.now() == 105.0
    clock.set(1.0)
    assert clock.now() == 1.0
    assert SystemClock().now() > 1_700_000_000


class TestProblemDetails:
    def test_document_and_titles(self) -> None:
        from pytrat.core import AuthenticationError, DependencyError, problem_details

        error = AuthorizationError(
            ReasonCode.TRANSACTION_CONTEXT_MISMATCH, "'amount_minor': differs"
        )
        assert problem_details(error) == {
            "type": "urn:pytrat:problem:TRANSACTION_CONTEXT_MISMATCH",
            "title": "Transaction not authorized",
            "status": 403,
            "reason_code": "TRANSACTION_CONTEXT_MISMATCH",
        }
        error.transaction_id = "txn-1"
        document = problem_details(error, include_detail=True)
        assert document["transaction_id"] == "txn-1"
        assert document["detail"] == "'amount_minor': differs"
        assert problem_details(TokenError(ReasonCode.TOKEN_EXPIRED, "x"))["status"] == 401
        assert problem_details(AuthenticationError(ReasonCode.WORKLOAD_UNAUTHENTICATED, "x"))[
            "title"
        ]
        assert problem_details(DependencyError("x"))["status"] == 503
