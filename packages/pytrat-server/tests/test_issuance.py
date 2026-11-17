"""Pure issuance planning (txn-tokens-11 §11.3, §13.6, §13.10, §13.14)."""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pytrat.core import FrozenClock, ReasonCode, Scope, SecretToken
from pytrat.server import (
    IssuancePolicy,
    JsonType,
    OAuthError,
    SubjectInfo,
    WorkloadIdentity,
    WorkloadIssuanceRule,
    plan_issuance,
)
from pytrat.server.forms import TokenRequest
from pytrat.server.issuance_policy import value_matches

NOW = 1_795_000_000
GATEWAY = WorkloadIdentity("api-gateway")


def rule(**overrides):
    data = {"scopes": ["a", "b"], "tctx": {"amount": "integer"}, "rctx": {"ip": "string"}}
    data.update(overrides)
    return WorkloadIssuanceRule.model_validate_json(__import__("json").dumps(data))


def policy(cap=True, **rule_overrides):
    return IssuancePolicy(
        workloads={"api-gateway": rule(**rule_overrides)}, cap_lifetime_at_subject_exp=cap
    )


def request(scope="a", audience="payments.internal", details=None, context=None, token="subject"):  # noqa: S107
    return TokenRequest(
        grant_type="g",
        requested_token_type="r",
        audience=audience,
        scope=Scope.parse(scope),
        subject_token=SecretToken(token),
        subject_token_type="t",
        request_details=details,
        request_context=context,
    )


def subject(scope="a b", exp=NOW + 300, **overrides):
    return SubjectInfo(
        sub="user:alice", scope=Scope.parse(scope) if scope else None, exp=exp, **overrides
    )


def plan(tts, req=None, subj=None, pol=None, **kwargs):
    return plan_issuance(
        req or request(),
        GATEWAY,
        subj or subject(),
        pol or policy(),
        tts.settings,
        FrozenClock(float(NOW)),
        "txn-1",
        **kwargs,
    )


def denied(tts, **kwargs):
    with pytest.raises(OAuthError) as info:
        plan(tts, **kwargs)
    return info.value


def test_claims_are_built_by_the_tts(tts):
    result = plan(
        tts, req=request(details={"amount": 5, "x": 1}, context={"ip": "1.1.1.1", "y": 2})
    )
    claims = result.claims
    assert (claims.txn, claims.sub, claims.req_wl, claims.aud) == (
        "txn-1",
        "user:alice",
        "api-gateway",
        "payments.internal",
    )
    assert (claims.iat, claims.exp) == (NOW, NOW + 60)
    assert dict(claims.tctx) == {"amount": 5}
    assert dict(claims.rctx) == {"ip": "1.1.1.1"}
    assert result.dropped_keys == ("tctx.x", "rctx.y")
    assert claims.agentic_ctx is None


def test_unknown_workload_is_unauthorized(tts):
    error = denied(tts, pol=IssuancePolicy())
    assert (error.error, error.reason) == (
        "unauthorized_client",
        ReasonCode.ISSUANCE_NOT_AUTHORIZED,
    )


def test_audience_restrictions(tts):
    assert denied(tts, req=request(audience="x")).error == "invalid_target"
    with pytest.raises(OAuthError):
        plan(tts, pol=policy(audiences=["payments.internal"]), req=request(audience="other"))


def test_workload_allowed_audiences_enforced(make_tts):
    def restrict(config):
        config["workloads"][0]["allowed_audiences"] = ["payments.internal"]

    tts = make_tts(restrict)
    assert plan(tts).claims.aud == "payments.internal"


def test_unknown_subject_scope_rejected_txn_tokens_11_s13_14(tts):
    """txn-tokens-11 §13.14."""
    error = denied(tts, subj=subject(scope=None))
    assert (error.error, error.reason) == ("invalid_scope", ReasonCode.SCOPE_INSUFFICIENT)


def test_empty_intersection_rejected(tts):
    assert denied(tts, req=request(scope="c")).error == "invalid_scope"
    assert denied(tts, req=request(scope="b"), subj=subject(scope="a")).error == "invalid_scope"


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])  # tts is read-only here
@given(
    requested=st.sets(st.sampled_from("abcd"), min_size=1),
    allowed=st.sets(st.sampled_from("abcd"), min_size=1),
    held=st.sets(st.sampled_from("abcd"), min_size=1),
)
def test_granted_scope_never_exceeds_any_bound_txn_tokens_11_s13_6(tts, requested, allowed, held):
    """txn-tokens-11 §13.6: granted ⊆ requested ∩ policy ∩ subject."""
    expected = requested & allowed & held
    kwargs = {
        "req": request(scope=" ".join(sorted(requested))),
        "subj": subject(scope=" ".join(sorted(held))),
        "pol": policy(scopes=sorted(allowed)),
    }
    if not expected:
        with pytest.raises(OAuthError, match="no requested scope"):
            plan(tts, **kwargs)
        return
    assert plan(tts, **kwargs).claims.scope.tokens == expected


def test_lifetime_caps(tts):
    assert plan(tts, pol=policy(max_lifetime_seconds=10)).claims.exp == NOW + 10
    # txn-tokens-11 §6, PyTraT default: capped at the subject's exp.
    assert plan(tts, subj=subject(exp=NOW + 20)).claims.exp == NOW + 20
    assert plan(tts, subj=subject(exp=NOW + 20), pol=policy(cap=False)).claims.exp == NOW + 60
    assert plan(tts, subj=subject(exp=None)).claims.exp == NOW + 60
    error = denied(tts, subj=subject(exp=NOW))
    assert (error.error, error.reason) == ("invalid_grant", ReasonCode.TOKEN_EXPIRED)


def test_act_copied_and_authn_asserted(tts):
    claims = plan(tts, subj=subject(act={"sub": "agent-x"}, authn={"acr": "2"})).claims
    assert claims.actor == "agent-x"
    assert dict(claims.rctx) == {"authn": {"acr": "2"}}


def test_invalid_claims_become_invalid_request(tts):
    error = denied(tts, subj=SubjectInfo(sub="x" * 5000, scope=Scope.of("a"), exp=None))
    assert error.error == "invalid_request"


def test_embedded_subject_token_refused_txn_tokens_11_s13_4(tts):
    """txn-tokens-11 §13.4."""
    req = request(
        token="eyJ.secret.token", details={"amount": 1}, context={"ip": "x eyJ.secret.token"}
    )
    assert denied(tts, req=req).reason is ReasonCode.CLAIM_INVALID


def test_dropped_key_names_are_audit_safe(tts):
    hostile = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln"
    result = plan(tts, req=request(details={hostile: 1}))
    assert hostile not in "".join(result.dropped_keys)
    assert result.dropped_keys[0].startswith("tctx.sha256:")


@pytest.mark.parametrize(
    ("value", "json_type", "ok"),
    [
        ("s", JsonType.STRING, True),
        (1, JsonType.STRING, False),
        (1, JsonType.INTEGER, True),
        (True, JsonType.INTEGER, False),
        (1.0, JsonType.INTEGER, False),
        (False, JsonType.BOOLEAN, True),
        (0, JsonType.BOOLEAN, False),
        ({"a": (1, "x")}, JsonType.OBJECT, True),
        ({"a": {"b": 1.5}}, JsonType.OBJECT, False),
        ((1, 2), JsonType.ARRAY, True),
        ([1, 2], JsonType.ARRAY, True),
        ((1, (2.5,)), JsonType.ARRAY, False),
        ("x", JsonType.ARRAY, False),
        (1.5, JsonType.NUMBER, True),
        (2, JsonType.NUMBER, True),
        (True, JsonType.NUMBER, False),
        (float("inf"), JsonType.NUMBER, False),
        ("1", JsonType.NUMBER, False),
    ],
)
def test_value_matches_is_strict(value, json_type, ok):
    """CLAUDE.md invariant 9: exact type equality; floats only when declared."""
    assert value_matches(value, json_type) is ok


def test_policy_model_validation():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        rule(scopes=["bad scope"])
    with pytest.raises(ValidationError):
        rule(rctx={"authn": "string"})
    with pytest.raises(ValidationError):
        rule(scopes=[])
    with pytest.raises(ValidationError):
        rule(tctx={"amount": "float"})
