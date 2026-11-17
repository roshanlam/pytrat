"""Subject token validation (txn-tokens-11 §11.2, §6, §13.14)."""

from __future__ import annotations

import pytest

from pytrat.core import ConfigurationError, FrozenClock, ReasonCode, SecretToken
from pytrat.core.crypto import sign_compact
from pytrat.server import (
    JwtAccessTokenValidator,
    JwtIssuer,
    OAuthError,
    SelfSignedValidator,
    UnsignedJsonValidator,
    WorkloadIdentity,
    WorkloadRegistry,
)

NOW = 1_795_000_000
IDP = "https://idp.test"
AUD = "https://api.example"
GATEWAY = WorkloadIdentity("api-gateway")


@pytest.fixture
def clock():
    return FrozenClock(float(NOW))


@pytest.fixture
def access(keys, clock):
    issuer = JwtIssuer(IDP, keys["idp"].key_set(), AUD, frozenset({"ES256"}))
    return JwtAccessTokenValidator([issuer], clock=clock)


def jwt(key, typ="at+jwt", **overrides):
    claims = {
        "iss": IDP,
        "aud": AUD,
        "sub": "user:alice",
        "scope": "a b",
        "iat": NOW,
        "exp": NOW + 60,
    }
    for name, value in overrides.items():
        if value is None:
            claims.pop(name)
        else:
            claims[name] = value
    return SecretToken(sign_compact(claims, key.private_key, alg="ES256", kid=key.kid, typ=typ))


def invalid(validator, token, workload=GATEWAY):
    with pytest.raises(OAuthError) as info:
        validator.validate(token, workload)
    return info.value


def test_access_token_yields_subject(access, keys):
    info = access.validate(
        jwt(keys["idp"], typ="JWT", act={"sub": "agent"}, client_id="c", acr="2", amr=["pwd"]),
        GATEWAY,
    )
    assert (info.sub, str(info.scope), info.exp, info.client_id) == (
        "user:alice",
        "a b",
        NOW + 60,
        "c",
    )
    assert info.act == {"sub": "agent"}
    assert dict(info.authn) == {"acr": "2", "amr": ["pwd"]}
    assert not info.client_credentials


def test_client_credentials_detection(access, keys):
    assert access.validate(jwt(keys["idp"], sub="svc", client_id="svc"), GATEWAY).client_credentials
    assert access.validate(jwt(keys["idp"], gty="client-credentials"), GATEWAY).client_credentials


def test_audience_list(access, keys):
    assert access.validate(jwt(keys["idp"], aud=["x", AUD]), GATEWAY).sub == "user:alice"
    assert invalid(access, jwt(keys["idp"], aud=["x"])).reason is ReasonCode.SUBJECT_TOKEN_INVALID
    assert invalid(access, jwt(keys["idp"], aud=5)).error == "invalid_grant"


def test_expired_access_token_txn_tokens_11_s6(access, keys):
    """txn-tokens-11 §6: no issuance once exp has passed; no leeway."""
    assert invalid(access, jwt(keys["idp"], exp=NOW)).reason is ReasonCode.TOKEN_EXPIRED


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"iss": "https://evil"}, ReasonCode.ISSUER_MISMATCH),
        ({"exp": None}, ReasonCode.SUBJECT_TOKEN_INVALID),
        ({"exp": "1"}, ReasonCode.SUBJECT_TOKEN_INVALID),
        ({"iat": NOW + 600}, ReasonCode.TOKEN_NOT_YET_VALID),
        ({"sub": None}, ReasonCode.SUBJECT_TOKEN_INVALID),
        ({"sub": ""}, ReasonCode.SUBJECT_TOKEN_INVALID),
        ({"scope": ["a"]}, ReasonCode.SUBJECT_TOKEN_INVALID),
        ({"scope": "a  b"}, ReasonCode.SUBJECT_TOKEN_INVALID),
        ({"act": "agent"}, ReasonCode.SUBJECT_TOKEN_INVALID),
        ({"client_id": 7}, ReasonCode.SUBJECT_TOKEN_INVALID),
    ],
)
def test_invalid_access_token_claims(access, keys, overrides, reason):
    assert invalid(access, jwt(keys["idp"], **overrides)).reason is reason


def test_scope_less_access_token_has_unknown_scope(access, keys):
    """txn-tokens-11 §13.14: reported as unknown; issuance then refuses it."""
    assert access.validate(jwt(keys["idp"], scope=None), GATEWAY).scope is None


def test_access_token_typ_enforced(access, keys):
    assert (
        invalid(access, jwt(keys["idp"], typ="txntoken+jwt")).reason
        is ReasonCode.TOKEN_TYPE_INVALID
    )


def test_issuer_algorithm_restriction(keys, clock):
    issuer = JwtIssuer(IDP, keys["idp"].key_set(), AUD, frozenset({"ES256"}))
    other = JwtIssuer("https://other", keys["api-gateway"].key_set(), AUD, frozenset({"PS256"}))
    validator = JwtAccessTokenValidator([issuer, other], clock=clock)
    token = jwt(keys["api-gateway"], iss="https://other")
    assert invalid(validator, token).error == "invalid_grant"


def test_shared_kid_between_issuers_is_config_error(keys, clock):
    a = JwtIssuer(IDP, keys["api-gateway"].key_set(), AUD, frozenset({"ES256"}))
    b = JwtIssuer("x", keys["attacker"].key_set(), AUD, frozenset({"ES256"}))
    with pytest.raises(ConfigurationError):
        JwtAccessTokenValidator([a, b], clock=clock)


@pytest.fixture
def self_signed(keys, clock):
    registry = WorkloadRegistry({"api-gateway": keys["api-gateway"].key_set()})
    return SelfSignedValidator(
        registry,
        tts_identifiers=frozenset({"https://tts", "https://tts/token"}),
        algorithms=frozenset({"ES256"}),
        clock=clock,
    )


def self_jwt(key, **overrides):
    defaults = {"iss": "api-gateway", "aud": "https://tts", "sub": "job:1", "scope": "a"}
    return jwt(key, typ="JWT", **{**defaults, **overrides})


def test_self_signed_valid_txn_tokens_11_s11_2_1(self_signed, keys):
    """txn-tokens-11 §11.2.1."""
    info = self_signed.validate(self_jwt(keys["api-gateway"], aud=["https://tts/token"]), GATEWAY)
    assert (info.sub, str(info.scope), info.client_id) == ("job:1", "a", None)


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"iss": "payment-service"}, ReasonCode.SUBJECT_TOKEN_INVALID),
        ({"aud": "https://elsewhere"}, ReasonCode.SUBJECT_TOKEN_INVALID),
        ({"iat": None}, ReasonCode.SUBJECT_TOKEN_INVALID),
        ({"exp": None}, ReasonCode.SUBJECT_TOKEN_INVALID),
        ({"iat": NOW + 600}, ReasonCode.TOKEN_NOT_YET_VALID),
        ({"iat": NOW - 3600, "exp": NOW + 10}, ReasonCode.TOKEN_EXPIRED),
        ({"exp": NOW - 1}, ReasonCode.TOKEN_EXPIRED),
        ({"sub": None}, ReasonCode.SUBJECT_TOKEN_INVALID),
    ],
)
def test_self_signed_rules_txn_tokens_11_s11_2_1(self_signed, keys, overrides, reason):
    """txn-tokens-11 §11.2.1: iss, sub, aud, iat, exp."""
    assert invalid(self_signed, self_jwt(keys["api-gateway"], **overrides)).reason is reason


def test_self_signed_with_another_workloads_key_is_rejected(self_signed, keys):
    """Attack: a workload presents a token self-signed by someone else."""
    error = invalid(self_signed, self_jwt(keys["payment-service"]))
    assert error.reason is ReasonCode.KEY_UNKNOWN
    error = invalid(self_signed, self_jwt(keys["api-gateway"]), WorkloadIdentity("unknown"))
    assert error.error == "invalid_grant"


@pytest.fixture
def unsigned(clock):
    return UnsignedJsonValidator(frozenset({"api-gateway"}), clock=clock)


def test_unsigned_json_txn_tokens_11_s11_2_2(unsigned):
    """txn-tokens-11 §11.2.2: sub REQUIRED."""
    info = unsigned.validate(
        SecretToken(f'{{"sub": "u", "scope": "a", "exp": {NOW + 5}}}'), GATEWAY
    )
    assert (info.sub, info.exp) == ("u", NOW + 5)


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ('{"scope": "a"}', ReasonCode.SUBJECT_TOKEN_INVALID),
        ("[1]", ReasonCode.TOKEN_MALFORMED),
        (f'{{"sub": "u", "exp": {NOW}}}', ReasonCode.TOKEN_EXPIRED),
        ('{"sub": "' + "x" * 20_000 + '"}', ReasonCode.TOKEN_MALFORMED),
    ],
)
def test_unsigned_json_invalid(unsigned, raw, reason):
    assert invalid(unsigned, SecretToken(raw)).reason is reason


def test_unsigned_json_disabled_for_unlisted_workload(unsigned):
    error = invalid(unsigned, SecretToken('{"sub": "u"}'), WorkloadIdentity("payment-service"))
    assert (error.error, error.reason) == (
        "unauthorized_client",
        ReasonCode.ISSUANCE_NOT_AUTHORIZED,
    )


def test_self_signed_subject_cannot_claim_a_delegated_agent(self_signed, keys):
    """PyTraT profile P28: a requester-asserted act could forge an agent identity."""
    token = self_jwt(keys["api-gateway"], act={"sub": "trusted-agent"})
    assert invalid(self_signed, token).reason is ReasonCode.ISSUANCE_NOT_AUTHORIZED


def test_unsigned_subject_cannot_claim_a_delegated_agent(unsigned):
    raw = SecretToken('{"sub": "user:1", "scope": "a", "act": {"sub": "trusted-agent"}}')
    assert invalid(unsigned, raw).reason is ReasonCode.ISSUANCE_NOT_AUTHORIZED
