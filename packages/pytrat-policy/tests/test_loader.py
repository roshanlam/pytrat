from __future__ import annotations

import copy
from pathlib import Path

import pytest

from pytrat.core import ConfigurationError, InMemoryReplayStore, ReasonCode, Scope
from pytrat.policy import (
    AgentRequirements,
    CompiledPolicy,
    PolicySet,
    load_policy,
    load_policy_text,
)

EXAMPLE = Path(__file__).parents[1] / "examples" / "policy.yaml"


def base_document() -> dict[str, object]:
    return {
        "version": 1,
        "trust_domain": "payments.internal",
        "resources": [
            {
                "name": "transfer",
                "path": "/internal/transfer",
                "method": "POST",
                "allowed_scopes": ["payments.transfer"],
            }
        ],
    }


def with_resource(**changes: object) -> dict[str, object]:
    document = base_document()
    resource = document["resources"][0]  # type: ignore[index]
    for key, value in changes.items():
        if value is None:
            resource.pop(key, None)
        else:
            resource[key] = value
    return document


def load_error(document: object) -> ConfigurationError:
    with pytest.raises(ConfigurationError) as info:
        load_policy(document)  # type: ignore[arg-type]
    return info.value


# ------------------------------------------------------------------ valid documents


def test_example_policy_loads() -> None:
    policy_set = load_policy(
        EXAMPLE, expected_trust_domain="payments.internal", replay_store=InMemoryReplayStore()
    )
    assert isinstance(policy_set, PolicySet)
    assert policy_set.trust_domain == "payments.internal"
    assert len(policy_set) == 3
    transfer = policy_set.for_route("POST", "/internal/transfer")
    assert transfer.policy_id == "transfer-execution"
    assert transfer.allowed_scopes == Scope.of("payments.transfer")
    assert transfer.allowed_callers == frozenset({"payment-service"})
    assert transfer.binding.fields == (
        "source_account",
        "destination_account",
        "amount_minor",
        "currency",
    )
    assert transfer.agents == AgentRequirements(
        enabled=True, maximum_hops=3, minimum_assurance="medium", require_chain_replacement=True
    )
    ledger = policy_set.for_route("POST", "/ledger/accounts/acc-1/postings")
    assert ledger.policy_id == "ledger-posting"
    assert ledger.single_use
    assert ledger.binding.fields == ("source_account", "amount_minor")
    assert not policy_set.for_route("GET", "/internal/health").require_transaction


def test_example_policy_loads_from_string_path_and_text() -> None:
    store = InMemoryReplayStore()
    from_str = load_policy(str(EXAMPLE), replay_store=store)
    from_text = load_policy_text(EXAMPLE.read_text(), replay_store=store)
    assert from_str.routes == from_text.routes


def test_yaml_and_programmatic_policies_are_equal() -> None:
    policy_set = load_policy(
        with_resource(
            bind_context=["amount_minor"],
            allowed_callers=["payment-service"],
            agents={"enabled": True, "maximum_hops": 2},
        )
    )
    built = CompiledPolicy.build(
        policy_id="transfer",
        allowed_scopes="payments.transfer",
        bind_context=["amount_minor"],
        allowed_callers=["payment-service"],
        agents=AgentRequirements(enabled=True, maximum_hops=2),
    )
    assert policy_set.for_route("POST", "/internal/transfer") == built


def test_custom_assurance_levels_are_used() -> None:
    document = with_resource(agents={"enabled": True, "minimum_assurance": "gold"})
    document["assurance_levels"] = ["bronze", "silver", "gold"]
    policy = load_policy(document).for_route("POST", "/internal/transfer")
    assert policy.assurance.levels == ("bronze", "silver", "gold")


def test_tuple_lists_in_mapping_input_are_accepted() -> None:
    document = with_resource(allowed_scopes=("payments.transfer",))
    assert load_policy(document).for_route("POST", "/internal/transfer")


# ------------------------------------------------------------------ invalid documents


def resource_with_agents(agents: dict[str, object]) -> dict[str, object]:
    return with_resource(agents=agents)


INVALID: list[tuple[str, dict[str, object], str]] = [
    (
        "typo in resource key",
        with_resource(allowed_scope=["x"]),
        "resources[0].allowed_scope: unknown key",
    ),
    (
        "typo in agents key",
        resource_with_agents({"enabled": True, "max_hops": 3}),
        "resources[0].agents.max_hops: unknown key",
    ),
    ("missing path", with_resource(path=None), "resources[0].path: required key is missing"),
    (
        "string boolean",
        with_resource(single_use="true"),
        "resources[0].single_use: Input should be a valid boolean",
    ),
    (
        "string integer hops",
        resource_with_agents({"enabled": True, "maximum_hops": "3"}),
        "resources[0].agents.maximum_hops",
    ),
    (
        "zero hops",
        resource_with_agents({"enabled": True, "maximum_hops": 0}),
        "resources[0].agents.maximum_hops: Input should be greater than or equal to 1",
    ),
    (
        "scalar instead of list",
        with_resource(allowed_scopes="payments.transfer"),
        "resources[0].allowed_scopes: expected a list",
    ),
    (
        "non-string scope",
        with_resource(allowed_scopes=[1]),
        "resources[0].allowed_scopes[0]: Input should be a valid string",
    ),
    (
        "bad bind_context",
        with_resource(bind_context=[1]),
        "resources[0].bind_context: must be a list of field paths",
    ),
    (
        "bad bind_context mapping",
        with_resource(bind_context={"a": 1}),
        "resources[0].bind_context: must be a list of field paths",
    ),
    (
        "bind_context scalar",
        with_resource(bind_context="amount"),
        "resources[0].bind_context: must be a list of field paths",
    ),
    (
        "malformed bind path",
        with_resource(bind_context=["a..b"]),
        "resources[0].bind_context: invalid binding path",
    ),
    (
        "tctx path bound twice",
        with_resource(bind_context={"a": "x", "b": "x"}),
        "resources[0].bind_context: a tctx path is bound more than once",
    ),
    (
        "invalid resource name",
        with_resource(name="has space"),
        "resources[0].name: String should match pattern",
    ),
    (
        "empty allowed_scopes",
        with_resource(allowed_scopes=[]),
        "resources[0].allowed_scopes: must not be empty when require_transaction is true",
    ),
    (
        "omitted allowed_scopes",
        with_resource(allowed_scopes=None),
        "resources[0].allowed_scopes: must not be empty when require_transaction is true",
    ),
    (
        "invalid scope token",
        with_resource(allowed_scopes=['has"quote']),
        "resources[0].allowed_scopes: contains a value that is not a valid scope-token",
    ),
    (
        "callers without workload identity",
        with_resource(require_workload_identity=False, allowed_callers=["svc"]),
        "resources[0].allowed_callers: cannot be combined with require_workload_identity: false",
    ),
    (
        "empty callers",
        with_resource(allowed_callers=[]),
        "resources[0].allowed_callers: must not be empty",
    ),
    (
        "scopes without transaction",
        with_resource(require_transaction=False),
        "resources[0].allowed_scopes: requires require_transaction: true",
    ),
    (
        "binding without transaction",
        with_resource(require_transaction=False, allowed_scopes=None, bind_context=["a"]),
        "resources[0].bind_context: requires require_transaction: true",
    ),
    (
        "unknown assurance level",
        resource_with_agents({"enabled": True, "minimum_assurance": "platinum"}),
        "resources[0].agents.minimum_assurance: is not a level in the assurance ordering",
    ),
    (
        "agent constraints while disabled",
        resource_with_agents({"maximum_hops": 3}),
        "resources[0].agents.enabled: agent constraints are set but agents.enabled is false",
    ),
    (
        "empty originators",
        resource_with_agents({"enabled": True, "allowed_originators": []}),
        "resources[0].agents.allowed_originators: must not be empty",
    ),
    (
        "single use without replay store",
        with_resource(single_use=True),
        "resources[0].single_use: requires a replay store",
    ),
    (
        "verified agent without directory",
        resource_with_agents({"enabled": True, "require_verified_agent": True}),
        "resources[0].agents.require_verified_agent: requires an agent directory",
    ),
    (
        "lower-case method",
        with_resource(method="post"),
        "resources[0].method: must be one of",
    ),
    ("unknown method", with_resource(method="BREW"), "resources[0].method: must be one of"),
    ("relative path", with_resource(path="internal"), "resources[0].path: must start with '/'"),
    (
        "partial-segment template",
        with_resource(path="/a/x{id}"),
        "resources[0].path: has an empty or invalid segment",
    ),
    (
        "empty segment",
        with_resource(path="/a//b"),
        "resources[0].path: has an empty or invalid segment",
    ),
    (
        "repeated parameter",
        with_resource(path="/a/{id}/{id}"),
        "resources[0].path: repeats a template parameter name",
    ),
    ("unsupported version", {**base_document(), "version": 2}, "version: unsupported"),
    (
        "boolean version",
        {**base_document(), "version": True},
        "version: Input should be a valid integer",
    ),
    ("missing version", {"trust_domain": "t", "resources": []}, "version: required key"),
    (
        "unknown top-level key",
        {**base_document(), "resource": []},
        "<mapping>: resource: unknown key",
    ),
    (
        "no resources",
        {**base_document(), "resources": []},
        "resources: Value should have at least 1 item",
    ),
    ("resources not a list", {**base_document(), "resources": {}}, "resources: expected a list"),
    (
        "duplicate assurance levels",
        {**resource_with_agents({"enabled": True}), "assurance_levels": ["a", "a"]},
        "assurance_levels: assurance levels must be unique",
    ),
]


@pytest.mark.parametrize(
    ("document", "expected"),
    [pytest.param(document, expected, id=name) for name, document, expected in INVALID],
)
def test_invalid_policy_fails_at_load_with_precise_message(
    document: dict[str, object], expected: str
) -> None:
    error = load_error(copy.deepcopy(document))
    assert expected in error.detail
    assert error.detail.startswith("<mapping>: ")


def test_invalid_policy_errors_are_policy_invalid() -> None:
    assert load_error(with_resource(method="post")).reason is ReasonCode.POLICY_INVALID


def test_missing_dependency_errors_are_dependency_unavailable() -> None:
    error = load_error(with_resource(single_use=True))
    assert error.reason is ReasonCode.DEPENDENCY_UNAVAILABLE


def test_error_location_names_the_failing_resource_index() -> None:
    document = base_document()
    second = {"name": "b", "path": "/b", "method": "GET", "allowed_scopes": ["s"], "oops": 1}
    document["resources"] = [*document["resources"], second]  # type: ignore[misc]
    assert "resources[1].oops: unknown key" in load_error(document).detail


def test_many_errors_are_truncated() -> None:
    document = with_resource(**{f"bad{i}": 1 for i in range(15)})
    assert "and 5 more" in load_error(document).detail


def test_duplicate_route_is_rejected() -> None:
    document = base_document()
    document["resources"] = [
        *document["resources"],  # type: ignore[misc]
        {"name": "again", "path": "/internal/transfer", "method": "POST", "allowed_scopes": ["s"]},
    ]
    assert (
        "resources[1].path: duplicate route POST /internal/transfer" in load_error(document).detail
    )


def test_same_path_different_method_is_allowed() -> None:
    document = base_document()
    document["resources"] = [
        *document["resources"],  # type: ignore[misc]
        {"name": "read", "path": "/internal/transfer", "method": "GET", "allowed_scopes": ["s"]},
    ]
    assert len(load_policy(document)) == 2


def test_overlapping_templates_are_rejected() -> None:
    document = base_document()
    document["resources"] = [
        {"name": "a", "path": "/a/{x}/c", "method": "GET", "allowed_scopes": ["s"]},
        {"name": "b", "path": "/a/b/{y}", "method": "GET", "allowed_scopes": ["s"]},
    ]
    detail = load_error(document).detail
    assert "resources[1].path: route GET /a/b/{y} overlaps GET /a/{x}/c" in detail


def test_duplicate_resource_name_is_rejected() -> None:
    document = base_document()
    document["resources"] = [
        *document["resources"],  # type: ignore[misc]
        {"name": "transfer", "path": "/other", "method": "POST", "allowed_scopes": ["s"]},
    ]
    assert "resources[1].name: duplicate resource name" in load_error(document).detail


def test_trust_domain_mismatch_is_rejected() -> None:
    with pytest.raises(ConfigurationError, match=r"trust_domain: does not match"):
        load_policy(base_document(), expected_trust_domain="other.internal")


def test_matching_trust_domain_is_accepted() -> None:
    assert load_policy(base_document(), expected_trust_domain="payments.internal")


def test_document_must_be_a_mapping() -> None:
    with pytest.raises(ConfigurationError, match="must be a mapping"):
        load_policy_text("- a\n- b\n")
    with pytest.raises(ConfigurationError, match="must be a mapping"):
        load_policy_text("")


# ------------------------------------------------------------------ YAML and files


def test_file_errors_name_the_file(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text("version: 1\ntrust_domain: t\nresources:\n  - name: x\n    path: /x\n")
    with pytest.raises(ConfigurationError) as info:
        load_policy(path)
    assert info.value.detail.startswith(f"{path}: resources[0].method: required key is missing")


def test_missing_file_is_a_configuration_error(tmp_path: Path) -> None:
    path = tmp_path / "missing.yaml"
    with pytest.raises(ConfigurationError, match=r"missing\.yaml: cannot read policy file"):
        load_policy(path)


def test_non_utf8_file_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "latin1.yaml"
    path.write_bytes(b"version: 1\ntrust_domain: caf\xe9\n")
    with pytest.raises(ConfigurationError, match="not valid UTF-8"):
        load_policy(path)


def test_invalid_yaml_reports_position_without_source_text() -> None:
    with pytest.raises(ConfigurationError) as info:
        load_policy_text("version: 1\nsecret: [unclosed-s3cr3t\n", source="p.yaml")
    assert info.value.detail.startswith("p.yaml: invalid YAML at line")
    assert "s3cr3t" not in info.value.detail


def test_unsafe_yaml_tags_are_rejected() -> None:
    text = "version: 1\nx: !!python/object/apply:os.system ['echo pwned']\n"
    with pytest.raises(ConfigurationError, match="invalid YAML"):
        load_policy_text(text)


def test_multiple_documents_are_rejected() -> None:
    with pytest.raises(ConfigurationError, match="invalid YAML"):
        load_policy_text("version: 1\n---\nversion: 1\n")


@pytest.mark.parametrize(
    "text",
    [
        "version: 2001-13-14\n",
        "version: !!float x\n",
        "version: !!int 0x\n",
        "[" * 2000 + "]" * 2000,
        "a: " + "{a: " * 2000 + "1" + "}" * 2000,
    ],
)
def test_constructor_errors_and_deep_nesting_are_configuration_errors(text: str) -> None:
    """Regression (found by fuzz/fuzz_policy_yaml.py): ValueError / RecursionError escaped."""
    with pytest.raises(ConfigurationError, match="invalid YAML") as excinfo:
        load_policy_text(text)
    assert excinfo.value.reason is ReasonCode.POLICY_INVALID


def test_yaml_error_without_mark_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    import yaml

    def explode(*args: object, **kwargs: object) -> object:
        raise yaml.YAMLError("boom")

    monkeypatch.setattr(yaml, "compose", explode)
    with pytest.raises(ConfigurationError, match=r"^POLICY_INVALID: <string>: invalid YAML$"):
        load_policy_text("version: 1\n")


def test_marked_yaml_error_without_position_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    import yaml

    def explode(*args: object, **kwargs: object) -> object:
        raise yaml.MarkedYAMLError()

    monkeypatch.setattr(yaml, "compose", explode)
    with pytest.raises(ConfigurationError, match=r"^POLICY_INVALID: <string>: invalid YAML$"):
        load_policy_text("version: 1\n")


def test_duplicate_yaml_key_is_rejected_with_line() -> None:
    text = (
        "version: 1\ntrust_domain: t\nresources:\n"
        "  - name: a\n    path: /a\n    method: GET\n"
        "    allowed_scopes: [s]\n    allowed_scopes: [admin]\n"
    )
    with pytest.raises(ConfigurationError, match="duplicate key 'allowed_scopes' at line 8"):
        load_policy_text(text)


def test_yaml_aliases_are_supported_and_visited_once() -> None:
    text = (
        "version: 1\ntrust_domain: t\nscopes: &s [s]\nresources:\n"
        "  - {name: a, path: /a, method: GET, allowed_scopes: *s}\n"
        "  - {name: b, path: /b, method: GET, allowed_scopes: *s}\n"
    )
    # The anchor itself is an unknown top-level key; the alias walk must still terminate.
    with pytest.raises(ConfigurationError, match="scopes: unknown key"):
        load_policy_text(text)


def test_version_is_checked_before_schema() -> None:
    text = "version: 2\ntrust_domain: t\nnew_feature: {}\nresources: []\n"
    with pytest.raises(ConfigurationError, match="version: unsupported policy version"):
        load_policy_text(text)


def test_non_scalar_yaml_key_is_rejected_by_schema() -> None:
    text = "version: 1\ntrust_domain: t\n? [a, b]\n: x\nresources: []\n"
    with pytest.raises(ConfigurationError, match="invalid YAML at line"):
        load_policy_text(text)
