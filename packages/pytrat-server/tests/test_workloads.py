"""Workload authentication (txn-tokens-11 §11.5, RFC 7523)."""

from __future__ import annotations

import pytest

from pytrat.core import (
    ConfigurationError,
    FrozenClock,
    InMemoryReplayStore,
    ReasonCode,
)
from pytrat.core.constants import CLIENT_ASSERTION_TYPE_JWT_BEARER
from pytrat.core.crypto import sign_compact
from pytrat.core.testing import generate_test_key
from pytrat.server import (
    CompositeAuthenticator,
    OAuthError,
    PrivateKeyJwtAuthenticator,
    TrustedProxyMtlsAuthenticator,
    WorkloadIdentity,
    WorkloadRegistry,
)
from pytrat.server.forms import ClientAuthParams, TokenRequest
from pytrat.server.settings import TrustedProxyConfig
from pytrat.server.workloads import CredentialsAbsentError

ENDPOINT = "https://tts.payments.internal/token"
NOW = 1_795_000_000


@pytest.fixture
def setup(keys):
    clock = FrozenClock(float(NOW))
    registry = WorkloadRegistry(
        {
            "api-gateway": keys["api-gateway"].key_set(),
            "payment-service": keys["payment-service"].key_set(),
        }
    )
    auth = PrivateKeyJwtAuthenticator(
        registry,
        token_endpoint=ENDPOINT,
        algorithms=frozenset({"ES256"}),
        replay_store=InMemoryReplayStore(clock=clock),
        clock=clock,
    )
    return clock, registry, auth


def assertion(key, workload="api-gateway", **overrides):
    claims = {
        "iss": workload,
        "sub": workload,
        "aud": ENDPOINT,
        "iat": NOW,
        "exp": NOW + 60,
        "jti": "jti-1",
    }
    for name, value in overrides.items():
        if value is None:
            claims.pop(name)
        else:
            claims[name] = value
    return sign_compact(claims, key.private_key, alg=key.alg, kid=key.kid, typ="JWT")


def request(raw_assertion=None, assertion_type=CLIENT_ASSERTION_TYPE_JWT_BEARER, client_id=None):
    from pytrat.core import Scope, SecretToken

    return TokenRequest(
        grant_type="g",
        requested_token_type="r",
        audience="payments.internal",
        scope=Scope.of("a"),
        subject_token=SecretToken("s"),
        subject_token_type="t",
        client=ClientAuthParams(
            client_id=client_id,
            client_assertion_type=assertion_type,
            client_assertion=SecretToken(raw_assertion) if raw_assertion else None,
        ),
    )


def fails(auth, req, headers=None, peer="127.0.0.1"):
    with pytest.raises(OAuthError) as info:
        auth.authenticate(req, headers or {}, peer)
    assert info.value.error == "invalid_client"
    assert info.value.status == 401
    return info.value


def test_valid_assertion_identifies_owner(setup, keys):
    _, _, auth = setup
    identity = auth.authenticate(
        request(assertion(keys["api-gateway"]), client_id="api-gateway"), {}, None
    )
    assert identity == WorkloadIdentity("api-gateway")


def test_aud_list_containing_endpoint_accepted(setup, keys):
    _, _, auth = setup
    raw = assertion(keys["api-gateway"], aud=["https://other", ENDPOINT])
    assert auth.authenticate(request(raw), {}, None).id == "api-gateway"


def test_replayed_client_assertion_is_rejected(setup, keys):
    """Attack: RFC 7523 jti replay."""
    _, _, auth = setup
    raw = assertion(keys["api-gateway"])
    auth.authenticate(request(raw), {}, None)
    assert fails(auth, request(raw)).reason is ReasonCode.REPLAY_DETECTED


def test_replay_store_full_is_dependency_failure(keys):
    clock = FrozenClock(float(NOW))
    auth = PrivateKeyJwtAuthenticator(
        WorkloadRegistry({"api-gateway": keys["api-gateway"].key_set()}),
        token_endpoint=ENDPOINT,
        algorithms=frozenset({"ES256"}),
        replay_store=InMemoryReplayStore(max_entries=0, clock=clock),
        clock=clock,
    )
    with pytest.raises(OAuthError) as info:
        auth.authenticate(request(assertion(keys["api-gateway"])), {}, None)
    assert (info.value.error, info.value.status) == ("temporarily_unavailable", 503)


def test_assertion_for_wrong_audience_is_rejected(setup, keys):
    """Attack: an assertion minted for another server is replayed here."""
    _, _, auth = setup
    fails(auth, request(assertion(keys["api-gateway"], aud="https://other/token")))
    fails(auth, request(assertion(keys["api-gateway"], aud=[1, ENDPOINT], jti="j2")))


@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "payment-service"},
        {"sub": "payment-service"},
        {"exp": None},
        {"exp": "soon"},
        {"exp": True},
        {"exp": NOW - 10},
        {"exp": NOW + 3600},
        {"iat": NOW + 600},
        {"nbf": NOW + 600},
        {"jti": None},
        {"jti": ""},
        {"jti": "x" * 300},
    ],
)
def test_invalid_assertion_claims_rejected(setup, keys, overrides):
    _, _, auth = setup
    error = fails(auth, request(assertion(keys["api-gateway"], **overrides)))
    assert error.reason is ReasonCode.WORKLOAD_UNAUTHENTICATED


def test_client_id_mismatch_rejected(setup, keys):
    _, _, auth = setup
    fails(auth, request(assertion(keys["api-gateway"]), client_id="payment-service"))


def test_wrong_assertion_type_or_missing_assertion(setup, keys):
    _, _, auth = setup
    fails(auth, request(assertion(keys["api-gateway"]), assertion_type="urn:other"))
    fails(auth, request(None))
    with pytest.raises(CredentialsAbsentError):
        auth.authenticate(request(None, assertion_type=None), {}, None)


def test_assertion_signed_by_other_workload_key_cannot_impersonate(setup, keys):
    """Attack: payment-service signs an assertion claiming to be api-gateway."""
    _, _, auth = setup
    raw = assertion(keys["payment-service"], workload="api-gateway")
    fails(auth, request(raw))


def test_unknown_kid_and_bad_signature_rejected(setup, keys):
    _, _, auth = setup
    fails(auth, request(assertion(generate_test_key("ES256"))))
    fails(auth, request(assertion(keys["attacker"])))
    fails(auth, request("not.a.jwt"))


def test_assertion_without_kid_rejected(setup, keys):
    _, _, auth = setup
    key = keys["api-gateway"]
    raw = sign_compact(
        {"iss": "api-gateway", "sub": "api-gateway", "aud": ENDPOINT, "exp": NOW + 5, "jti": "k"},
        key.private_key,
        alg="ES256",
        kid=None,
    )
    fails(auth, request(raw))


def test_registry_rejects_shared_kid_and_comma_ids(keys):
    with pytest.raises(ConfigurationError):
        WorkloadRegistry({"a": keys["api-gateway"].key_set(), "b": keys["attacker"].key_set()})
    with pytest.raises(ConfigurationError):
        WorkloadRegistry({"a,b": keys["api-gateway"].key_set()})
    with pytest.raises(ConfigurationError):
        WorkloadRegistry({"": keys["api-gateway"].key_set()})


def test_registry_lookups(setup):
    _, registry, _ = setup
    assert registry.is_registered("api-gateway")
    assert registry.keys_for("nobody") is None
    assert registry.all_keys.get(None) is None


@pytest.fixture
def proxy(setup):
    _, registry, _ = setup
    config = TrustedProxyConfig(
        header="X-Client-Cert-SPIFFE-ID", trusted_cidrs=("10.0.0.0/8", "fd00::/8")
    )
    return TrustedProxyMtlsAuthenticator(config, registry)


def test_trusted_proxy_header_from_trusted_peer(proxy):
    headers = {"x-client-cert-spiffe-id": ("payment-service",)}
    assert proxy.authenticate(request(None, None), headers, "10.1.2.3").id == "payment-service"
    assert proxy.authenticate(request(None, None), headers, "fd00::1").id == "payment-service"


@pytest.mark.parametrize("peer", ["192.168.1.1", None, "not-an-ip"])
def test_trusted_proxy_header_from_untrusted_peer_is_rejected(proxy, peer):
    """Attack: a workload sets the identity header itself, bypassing the proxy."""
    headers = {"x-client-cert-spiffe-id": ("payment-service",)}
    fails(proxy, request(None, None), headers, peer)


@pytest.mark.parametrize("values", [("payment-service", "api-gateway"), ("",), ("unregistered",)])
def test_trusted_proxy_header_values_validated(proxy, values):
    fails(proxy, request(None, None), {"x-client-cert-spiffe-id": values}, "10.0.0.1")


def test_trusted_proxy_client_id_must_match(proxy):
    headers = {"x-client-cert-spiffe-id": ("payment-service",)}
    fails(proxy, request(None, None, client_id="api-gateway"), headers, "10.0.0.1")


def test_trusted_proxy_absent_header(proxy):
    with pytest.raises(CredentialsAbsentError):
        proxy.authenticate(request(None, None), {}, "10.0.0.1")


def test_composite_requires_exactly_one_method(setup, proxy, keys):
    _, _, jwt_auth = setup
    composite = CompositeAuthenticator([jwt_auth, proxy])
    headers = {"x-client-cert-spiffe-id": ("payment-service",)}
    assert composite.authenticate(request(None, None), headers, "10.0.0.1").id == "payment-service"
    assert (
        composite.authenticate(request(assertion(keys["api-gateway"])), {}, None).id
        == "api-gateway"
    )
    with pytest.raises(CredentialsAbsentError):
        composite.authenticate(request(None, None), {}, None)
    both = request(assertion(keys["api-gateway"], jti="both"))
    fails(composite, both, headers, "10.0.0.1")
    # A present-but-invalid credential is never "absent": no fallback to another method.
    fails(composite, request("garbage"), headers, "10.0.0.1")
    with pytest.raises(ValueError, match="at least one"):
        CompositeAuthenticator([])


async def test_trusted_proxy_over_http(make_tts):
    def enable(config):
        config["workload_auth"] = {
            "trusted_proxy": {"header": "X-Client-Cert-SPIFFE-ID", "trusted_cidrs": ["10.0.0.0/8"]}
        }

    tts = make_tts(enable)
    form = tts.form(authenticate=False)
    headers = {"X-Client-Cert-SPIFFE-ID": "api-gateway"}
    ok = await tts.post(form, headers=headers, client=("10.9.9.9", 1234))
    assert ok.status_code == 200
    attack = await tts.post(form, headers=headers, client=("203.0.113.5", 1234))
    assert attack.status_code == 401
