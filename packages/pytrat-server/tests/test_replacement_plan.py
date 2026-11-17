"""Pure replacement planning (txn-tokens-11 §13.15) and other edge paths."""

from __future__ import annotations

from dataclasses import replace

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pytrat.core import ReasonCode, Scope, SecretToken
from pytrat.core.testing import FrozenClock, TokenFactory
from pytrat.server import (
    IssuancePolicy,
    JsonType,
    OAuthError,
    WorkloadIdentity,
    WorkloadIssuanceRule,
    create_app,
    plan_replacement,
    txn_token_verifier,
)
from pytrat.server import replacement as replacement_module
from pytrat.server.errors import OAuthErrorCode, translate
from pytrat.server.forms import TokenRequest

NOW = 1_795_000_000
REQUESTER = WorkloadIdentity("payment-service")
POLICY = IssuancePolicy(
    workloads={
        "payment-service": WorkloadIssuanceRule(
            scopes=("a", "b", "c"), may_replace=True, rctx={"k": JsonType.STRING}
        )
    }
)


@pytest.fixture
def factory(keys):
    return TokenFactory(
        key=keys["tts"], trust_domain="payments.internal", clock=FrozenClock(float(NOW))
    )


def verified(tts, factory, **claims):
    claims.setdefault("iss", "https://tts.payments.internal")
    claims.setdefault("scope", "a b")
    raw = factory.mint(**claims)
    return txn_token_verifier(tts.settings, factory.key.key_set(), factory.clock).verify(raw)


def request(scope="a", audience="payments.internal", context=None, details=None):
    return TokenRequest(
        grant_type="g",
        requested_token_type="r",
        audience=audience,
        scope=Scope.parse(scope),
        subject_token=SecretToken("subject"),
        subject_token_type="t",
        request_context=context,
        request_details=details,
    )


def plan(tts, current, req=None, count=0, clock=None):
    return plan_replacement(
        current,
        req or request(),
        REQUESTER,
        POLICY,
        tts.settings,
        clock or FrozenClock(float(NOW)),
        count,
    )


def test_optional_claims_absent_are_not_invented(tts, factory):
    # Planning is pure: exercise an input without iss using a verifier that does not require it.
    raw = factory.mint(iss=None, tctx=None, rctx=None, scope="a b")
    current = factory.verifier().verify(raw)
    result = plan(tts, current)
    assert result.claims.iss is None
    assert result.claims.tctx is None
    assert result.claims.rctx is None
    assert result.requester_is_agent is False
    assert result.extends_lifetime is False


def test_rctx_only_gains_members(tts, factory):
    current = verified(tts, factory, rctx={"k": "original"})
    result = plan(tts, current, req=request(context={"k": "forged"}, details={"amount": 1}))
    assert dict(result.claims.rctx) == {"k": "original"}
    assert result.dropped_keys == ("tctx.amount", "rctx.k")


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(requested=st.sets(st.sampled_from("abcd"), min_size=1))
def test_scope_only_shrinks_txn_tokens_11_s13_15(tts, factory, requested):
    """txn-tokens-11 §13.15 / invariant 5: replacement scope ⊆ input scope."""
    current = verified(tts, factory, scope="a b")
    req = request(scope=" ".join(sorted(requested)))
    if not requested <= {"a", "b"}:
        with pytest.raises(OAuthError, match="exceeds the subject"):
            plan(tts, current, req=req)
        return
    result = plan(tts, current, req=req)
    assert result.claims.scope.tokens == requested
    assert (result.claims.txn, result.claims.sub) == (current.claims.txn, current.claims.sub)


def test_defence_in_depth_attenuation_check(tts, factory, monkeypatch):
    """If planning ever produced a widening token, it is refused before signing."""
    current = verified(tts, factory)
    real = replacement_module.plan_agent_replacement

    def widening(*args, **kwargs):
        return replace(real(*args, **kwargs), sub="user:mallory")

    monkeypatch.setattr(replacement_module, "plan_agent_replacement", widening)
    with pytest.raises(OAuthError) as info:
        plan(tts, current)
    assert (info.value.error, info.value.reason) == (
        "invalid_grant",
        ReasonCode.REPLACEMENT_WIDENS_AUTHORIZATION,
    )


def test_translate_passes_oauth_errors_through():
    error = OAuthError(OAuthErrorCode.INVALID_SCOPE, "x", ReasonCode.SCOPE_INSUFFICIENT)
    assert translate(error, OAuthErrorCode.SERVER_ERROR) is error


async def test_lifespan_runs_shutdown_callbacks(tts):
    closed = []

    async def close():
        closed.append(True)

    app = create_app(replace(tts.components, on_shutdown=(close,)))
    async with app.router.lifespan_context(app):
        assert closed == []
    assert closed == [True]


async def test_proxy_only_authentication(make_tts):
    def proxy_only(config):
        config["workload_auth"] = {
            "private_key_jwt": False,
            "trusted_proxy": {"header": "X-Workload", "trusted_cidrs": ["127.0.0.0/8"]},
        }

    tts = make_tts(proxy_only)
    ok = await tts.post(tts.form(authenticate=False), headers={"X-Workload": "api-gateway"})
    assert ok.status_code == 200
    assertion_only = await tts.post(tts.form())
    assert assertion_only.status_code == 401
