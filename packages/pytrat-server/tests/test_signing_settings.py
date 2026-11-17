"""Signing key ring and configuration loading."""

from __future__ import annotations

import json
import os

import pytest
import yaml

from pytrat.core import ConfigurationError, StaticKeySet, TokenVerifier, VerifierSettings
from pytrat.core.crypto import peek_header, private_key_to_pem
from pytrat.core.testing import FrozenClock, generate_test_key
from pytrat.server import (
    FileKeySigner,
    KeyRingSigner,
    SigningKey,
    build_components,
    create_app_from_settings,
    load_settings,
    parse_settings,
)
from pytrat.server.settings import KeyState


def ring(*states):
    return [
        SigningKey(kid=f"k{i}", alg="ES256", private_key=generate_test_key().private_key, state=s)
        for i, s in enumerate(states)
    ]


def test_signs_with_active_and_publishes_all_txn_tokens_11_s13_11():
    """txn-tokens-11 §13.11: rotation; retiring keys stay published."""
    keys = ring(KeyState.RETIRING, KeyState.ACTIVE)
    signer = KeyRingSigner(keys)
    token = signer.sign(
        {"aud": "d", "txn": "t", "sub": "s", "scope": "a", "req_wl": "w", "iat": 1, "exp": 2}
    )
    header = peek_header(token, max_bytes=4096)
    assert (header.kid, header.alg, signer.active_kid) == ("k1", "ES256", "k1")
    assert [k["kid"] for k in signer.jwks()["keys"]] == ["k0", "k1"]
    assert "private" not in repr(signer)
    assert "k1" in repr(signer)
    assert "private_key" not in repr(keys[0])


def test_token_signed_by_retiring_key_still_verifies():
    old, new = ring(KeyState.ACTIVE, KeyState.ACTIVE)
    payload = {
        "aud": "d",
        "txn": "t",
        "sub": "s",
        "scope": "a",
        "req_wl": "w",
        "iat": 100,
        "exp": 110,
    }
    before = KeyRingSigner([old]).sign(payload)
    after_rotation = KeyRingSigner(
        [SigningKey(old.kid, old.alg, old.private_key, KeyState.RETIRING), new]
    )
    verifier = TokenVerifier(
        VerifierSettings(trust_domain="d", algorithms=frozenset({"ES256"})),
        StaticKeySet.from_jwks(after_rotation.jwks()),
        FrozenClock(105.0),
    )
    assert verifier.verify(before).claims.txn == "t"


@pytest.mark.parametrize(
    "states",
    [(), (KeyState.RETIRING,), (KeyState.ACTIVE, KeyState.ACTIVE)],
)
def test_exactly_one_active_key(states):
    with pytest.raises(ConfigurationError):
        KeyRingSigner(ring(*states))


def test_duplicate_kids_rejected():
    keys = ring(KeyState.ACTIVE, KeyState.RETIRING)
    with pytest.raises(ConfigurationError):
        KeyRingSigner([keys[0], SigningKey("k0", "ES256", keys[1].private_key, KeyState.RETIRING)])


def test_key_algorithm_mismatch_rejected():
    with pytest.raises(ConfigurationError):
        KeyRingSigner([SigningKey("k", "PS256", generate_test_key().private_key)])


def test_world_readable_key_file_refused(tmp_path):
    path = tmp_path / "key.pem"
    path.write_bytes(private_key_to_pem(generate_test_key().private_key))
    os.chmod(path, 0o644)
    with pytest.raises(ConfigurationError, match="group or others"):
        FileKeySigner.load_key_file(path)
    assert FileKeySigner.load_key_file(path, allow_insecure_permissions=True) is not None
    with pytest.raises(ConfigurationError, match="could not be read"):
        FileKeySigner.load_key_file(tmp_path / "missing.pem")
    os.chmod(path, 0o600)
    path.write_bytes(b"not a key")
    with pytest.raises(ConfigurationError):
        FileKeySigner.load_key_file(path)


def test_from_settings_respects_permission_flag(config, tmp_path):
    os.chmod(tmp_path / "tts.pem", 0o640)
    settings = parse_settings(config, tmp_path)
    with pytest.raises(ConfigurationError):
        FileKeySigner.from_settings(settings)
    assert (
        FileKeySigner.from_settings(settings, allow_insecure_permissions=True).active_kid == "tts-1"
    )


def test_load_settings_resolves_relative_paths(config, tmp_path):
    path = tmp_path / "tts.yaml"
    path.write_text(yaml.safe_dump(config))
    settings = load_settings(path)
    assert settings.signing_keys[0].private_key_path == tmp_path.resolve() / "tts.pem"
    assert settings.token_lifetime_seconds == 60
    assert settings.workload("api-gateway") is not None
    assert settings.workload("nobody") is None


def test_create_app_from_settings_with_sqlite(config, tmp_path):
    config["audit_db_path"] = "audit.db"
    config["agents"] = {"enabled": False}
    path = tmp_path / "tts.yaml"
    path.write_text(yaml.safe_dump(config))
    app = create_app_from_settings(path)
    assert app.title.startswith("PyTraT")


@pytest.mark.parametrize(
    "text",
    [
        "- a list",
        "a: [unclosed",
        "when: 2024-01-01\n",
        # Regression (same class as fuzz/fuzz_policy_yaml.py findings): ValueError and
        # RecursionError escaped load_settings.
        "when: 2024-13-01\n",
        "a: !!float x\n",
        "a: !!int \n",
        "a: !!bool x\n",
        "a: !!timestamp x\n",
        "a: " + "[" * 2000 + "]" * 2000,
    ],
)
def test_load_settings_rejects_bad_documents(tmp_path, text):
    path = tmp_path / "bad.yaml"
    path.write_text(text)
    with pytest.raises(ConfigurationError):
        load_settings(path)


def test_load_settings_rejects_undecodable_file(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_bytes(b"\xff\xfe")
    with pytest.raises(ConfigurationError):
        load_settings(path)


def test_load_settings_missing_file(tmp_path):
    with pytest.raises(ConfigurationError, match="could not be read"):
        load_settings(tmp_path / "missing.yaml")


def mutate(config, path, value):
    target = config
    for part in path[:-1]:
        target = target[part]
    if value is None:
        del target[path[-1]]
    else:
        target[path[-1]] = value


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("unknown_key",), 1),
        (("token_lifetime_seconds",), 301),
        (("token_lifetime_seconds",), "60"),
        (("token_endpoint",), "/token"),
        (("algorithms",), ["HS256"]),
        (("algorithms",), ["XX999"]),
        (("signing_keys", 1, "state"), "active"),
        (("signing_keys", 1, "kid"), "tts-1"),
        (("signing_keys", 0, "alg"), "PS256"),
        (("workloads", 0, "id"), "a,b"),
        (("workloads", 1, "id"), "api-gateway"),
        (("workloads", 0, "jwks"), {"keys": []}),
        (("workloads", 1, "jwks"), None),
        (("workloads", 0, "allowed_audiences"), ["other"]),
        (("issuance_policy", "workloads", "ghost"), {"scopes": ["a"]}),
        (("issuance_policy", "workloads", "api-gateway", "audiences"), ["other"]),
        (("subject_tokens", "unsigned_json", "allowed_workloads"), ["ghost"]),
        (("subject_tokens", "jwt_access_token", 0, "algorithms"), ["none"]),
        (("agents",), {"enabled": True}),
        (("agents",), {"assurance_levels": ["a", "a"]}),
        (("agents",), {"default_assurance": "nope"}),
        (("workload_auth",), {"private_key_jwt": False}),
        (("workload_auth",), {"trusted_proxy": {"header": "X", "trusted_cidrs": ["10.0.0.1/8"]}}),
        (("workload_auth",), {"trusted_proxy": {"header": "X", "trusted_cidrs": []}}),
        (("max_request_bytes",), 10),
    ],
)
def test_invalid_settings_rejected(config, tmp_path, path, value):
    mutate(config, path, value)
    with pytest.raises(ConfigurationError) as info:
        parse_settings(config, tmp_path)
    assert "secret" not in str(info.value)


def test_settings_reject_non_json_values(config, tmp_path):
    config["max_request_bytes"] = float("nan")
    with pytest.raises(ConfigurationError, match="plain JSON"):
        parse_settings(config, tmp_path)


def test_settings_are_frozen(config, tmp_path):
    settings = parse_settings(config, tmp_path)
    with pytest.raises(ValueError, match="frozen"):
        settings.trust_domain = "x"  # type: ignore[misc]


def test_build_components_with_agents(config, tmp_path):
    (tmp_path / "agents.yaml").write_text(json.dumps({"agents": []}))
    config["agents"] = {"enabled": True, "registry_path": "agents.yaml", "max_hops": 3}
    components = build_components(parse_settings(config, tmp_path))
    assert components.agent_profile is not None
    assert components.agent_profile.limits.max_hops == 3


def test_build_components_minimal(config, tmp_path):
    config["subject_tokens"] = {}
    components = build_components(parse_settings(config, tmp_path))
    assert components.subject_validators == {}


def test_example_config_is_valid(tmp_path):
    """The shipped example parses (its key files are not shipped, so only the schema is checked)."""
    from pathlib import Path

    example = Path(__file__).parents[1] / "examples" / "tts.yaml"
    settings = load_settings(example)
    assert settings.trust_domain
    assert settings.agents.enabled is False
