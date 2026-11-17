from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from pytrat.agents import (
    SQLITE_SCHEMA,
    AgentRecord,
    AssuranceOrdering,
    InMemoryAgentStore,
    SqliteAgentStore,
    YamlAgentStore,
)
from pytrat.core import ConfigurationError, DependencyError, ReasonCode

YAML_DOC = """
agents:
  - id: billing-agent
    name: Billing agent
    owner: payments-team
    assurance_level: high
    version: 2.4.1
    provenance: "sha256:abc"
    client_id: billing-client
    attributes: {tee: sgx}
  - id: report-agent
    name: Report agent
    owner: reporting
    assurance_level: low
    version: "1"
    provenance: git
"""


def record(**overrides: object) -> AgentRecord:
    fields: dict[str, object] = {
        "id": "a1",
        "name": "A",
        "owner": "team",
        "assurance_level": "low",
        "version": "1",
        "provenance": "git",
    }
    fields.update(overrides)
    return AgentRecord(**fields)  # type: ignore[arg-type]


# ---------------------------------------------------------------- AgentRecord


def test_record_attributes_are_copied_and_frozen() -> None:
    source = {"tee": "sgx"}
    rec = record(attributes=source)
    source["tee"] = "none"
    assert rec.attributes["tee"] == "sgx"
    with pytest.raises(TypeError):
        rec.attributes["tee"] = "x"  # type: ignore[index]


def test_record_rejects_empty_id_and_client_id() -> None:
    with pytest.raises(ConfigurationError):
        record(id="")
    with pytest.raises(ConfigurationError):
        record(client_id="")


# ---------------------------------------------------------------- in-memory


def test_in_memory_lookups() -> None:
    store = InMemoryAgentStore([record(client_id="c1"), record(id="a2")])
    assert store.get("a1") is not None
    assert store.get("missing") is None
    assert store.by_client_id("c1") == store.get("a1")
    assert store.by_client_id("nope") is None
    assert store.is_registered("a2")
    assert not store.is_registered("zzz")
    assert len(store) == 2


def test_in_memory_rejects_duplicates_and_unknown_levels() -> None:
    """agent-profile-03 §3.6.2: assurance_level must be a deployment-defined level."""
    with pytest.raises(ConfigurationError):
        InMemoryAgentStore([record(), record()])
    with pytest.raises(ConfigurationError):
        InMemoryAgentStore([record(client_id="c"), record(id="a2", client_id="c")])
    with pytest.raises(ConfigurationError):
        InMemoryAgentStore([record(assurance_level="ultra")])
    custom = AssuranceOrdering(("bronze", "gold"))
    assert InMemoryAgentStore([record(assurance_level="gold")], ordering=custom).get("a1")


# ---------------------------------------------------------------- YAML


def test_yaml_store_loads(tmp_path: Path) -> None:
    path = tmp_path / "agents.yaml"
    path.write_text(YAML_DOC)
    store = YamlAgentStore(path)
    billing = store.by_client_id("billing-client")
    assert billing is not None
    assert billing.id == "billing-agent"
    assert billing.attributes == {"tee": "sgx"}
    assert store.is_registered("report-agent")
    report = store.get("report-agent")
    assert report is not None
    assert report.client_id is None


@pytest.mark.parametrize(
    "document",
    [
        "agents: [",  # invalid YAML
        "{}",  # missing 'agents'
        "agents:\n  - id: x\n",  # missing fields
        YAML_DOC.replace("tee: sgx", "tee: 1"),  # non-string attribute (strict)
        YAML_DOC.replace('version: "1"', "version: 1"),  # int is not str (strict)
        YAML_DOC + "    extra: field\n",  # unknown key
        YAML_DOC.replace("assurance_level: low", "assurance_level: ultra"),  # unknown level
        "agents: !!python/object/apply:os.system ['true']",  # unsafe tag
    ],
)
def test_yaml_store_rejects_invalid_documents(tmp_path: Path, document: str) -> None:
    path = tmp_path / "agents.yaml"
    path.write_text(document)
    with pytest.raises(ConfigurationError):
        YamlAgentStore(path)


def test_yaml_store_unreadable_file_is_dependency_error(tmp_path: Path) -> None:
    with pytest.raises(DependencyError) as excinfo:
        YamlAgentStore(tmp_path / "missing.yaml")
    assert excinfo.value.reason is ReasonCode.DEPENDENCY_UNAVAILABLE


# ---------------------------------------------------------------- SQLite


def _db(tmp_path: Path, rows: list[tuple[object, ...]], *, schema: str = SQLITE_SCHEMA) -> Path:
    path = tmp_path / "agents.db"
    with closing(sqlite3.connect(path)) as connection:
        connection.execute(schema)
        connection.executemany("INSERT INTO agents VALUES (?, ?, ?, ?, ?, ?, ?, ?)", rows)
        connection.commit()
    return path


GOOD_ROW = ("a1", "A", "team", "high", "1", "git", "c1", '{"tee": "sgx"}')


def test_sqlite_store_lookups(tmp_path: Path) -> None:
    path = _db(tmp_path, [GOOD_ROW, ("a2", "B", "team", "low", "1", "git", None, "{}")])
    store = SqliteAgentStore(path)
    a1 = store.get("a1")
    assert a1 is not None
    assert a1.attributes == {"tee": "sgx"}
    assert a1.client_id == "c1"
    assert store.by_client_id("c1") == a1
    assert store.get("missing") is None
    assert store.is_registered("a2")
    assert not store.is_registered("a3")


def test_sqlite_store_is_parametrised(tmp_path: Path) -> None:
    store = SqliteAgentStore(_db(tmp_path, [GOOD_ROW]))
    assert store.get("x' OR '1'='1") is None


def test_sqlite_store_is_read_only(tmp_path: Path) -> None:
    path = _db(tmp_path, [GOOD_ROW])
    store = SqliteAgentStore(path)
    with (
        pytest.raises(sqlite3.OperationalError),
        closing(sqlite3.connect(store._uri, uri=True)) as connection,
    ):
        connection.execute("DELETE FROM agents")


def test_registry_unavailable_fails_closed(tmp_path: Path) -> None:
    store = SqliteAgentStore(tmp_path / "does-not-exist.db")
    with pytest.raises(DependencyError) as excinfo:
        store.get("a1")
    assert excinfo.value.reason is ReasonCode.DEPENDENCY_UNAVAILABLE
    with pytest.raises(DependencyError):
        store.by_client_id("c1")
    with pytest.raises(DependencyError):
        store.is_registered("a1")


@pytest.mark.parametrize(
    "row",
    [
        ("a1", "", "team", "high", "1", "git", None, "{}"),  # empty name
        ("a1", "A", "team", "ultra", "1", "git", None, "{}"),  # unknown level
        ("a1", "A", "team", "high", "1", "git", 7, "{}"),  # non-text client_id
        ("a1", "A", "team", "high", "1", "git", None, "not json"),
        ("a1", "A", "team", "high", "1", "git", None, "[]"),
        ("a1", "A", "team", "high", "1", "git", None, '{"k": 1}'),
        ("a1", "A", "team", "high", "1", "git", None, 5),
    ],
)
def test_sqlite_invalid_row_fails_closed(tmp_path: Path, row: tuple[object, ...]) -> None:
    loose = SQLITE_SCHEMA.replace("TEXT", "").replace("DEFAULT '{}'", "")
    store = SqliteAgentStore(_db(tmp_path, [row], schema=loose))
    with pytest.raises(DependencyError):
        store.get("a1")


def test_sqlite_ambiguous_client_id_fails_closed(tmp_path: Path) -> None:
    schema = SQLITE_SCHEMA.replace("client_id       TEXT UNIQUE", "client_id TEXT")
    rows = [GOOD_ROW, ("a2", "B", "team", "low", "1", "git", "c1", "{}")]
    store = SqliteAgentStore(_db(tmp_path, rows, schema=schema))
    with pytest.raises(DependencyError):
        store.by_client_id("c1")


def test_stores_satisfy_policy_agent_directory_shape(tmp_path: Path) -> None:
    """Structural compatibility with pytrat.policy's AgentDirectory (is_registered)."""
    for store in (InMemoryAgentStore([record()]), SqliteAgentStore(_db(tmp_path, [GOOD_ROW]))):
        assert callable(store.is_registered)
        assert store.is_registered("a1") is True
