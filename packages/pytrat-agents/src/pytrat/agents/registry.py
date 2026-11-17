"""The Agent Attribute Store: the trusted source of agent identity and posture.

agent-profile-03 §3.6.2: posture, provenance and attestation attributes "MUST NOT be sourced from
agent self-assertion". The API enforces this by shape: an :class:`AgentRecord` is only ever
returned by a store that the deployment configured, keyed by an identifier the TTS or resource
server already verified. No function in :mod:`pytrat.agents` accepts agent-supplied attributes.

agent-profile-03 §5.10: the store is security-critical. The stores here are read-only; writes
belong to the deployment pipeline, not to this library.

Every lookup either returns a record, returns ``None`` (not registered), or raises
:class:`~pytrat.core.errors.DependencyError` if the store cannot answer. An unavailable store is
never treated as "not registered".
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Mapping
from contextlib import closing
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Final, Protocol

import yaml
from pydantic import BaseModel, ConfigDict, StringConstraints, ValidationError

from pytrat.core.assurance import AssuranceOrdering
from pytrat.core.errors import ConfigurationError, DependencyError

__all__ = [
    "SQLITE_SCHEMA",
    "AgentAttributeStore",
    "AgentRecord",
    "InMemoryAgentStore",
    "SqliteAgentStore",
    "YamlAgentStore",
]

_EMPTY: Final[Mapping[str, str]] = MappingProxyType({})


@dataclass(frozen=True, slots=True)
class AgentRecord:
    """One registered agent, as recorded by the deployment (agent-profile-03 §3.6.2).

    Attributes:
        id: Agent identifier used in ``agentic_ctx`` (``proximate_agent.id`` / ``originator.id``).
        name: Human-readable name (``agent_name`` in §3.6.2).
        owner: Owning team or principal, for incident response.
        assurance_level: Level used for ``min_assurance_level`` (§3.6.2). Validated against the
            deployment's :class:`AssuranceOrdering` when the store is built.
        version: Software version identifier (provenance, §3.6.2).
        provenance: Manifest or source reference (§3.6.2).
        attributes: Further posture attributes, string to string. Frozen.
        client_id: OAuth ``client_id`` of the agent, if it has one (§3.6.1, §3.6.2).
    """

    id: str
    name: str
    owner: str
    assurance_level: str
    version: str
    provenance: str
    attributes: Mapping[str, str] = field(default=_EMPTY)
    client_id: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            raise ConfigurationError("agent record id must be non-empty")
        if self.client_id == "":
            raise ConfigurationError("agent record client_id must be non-empty when set")
        # Copy and freeze: a caller keeping a reference to the original dict cannot mutate us.
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))


class AgentAttributeStore(Protocol):
    """Read-only lookup of registered agents.

    Implementations return ``None`` only for "not registered" and raise
    :class:`~pytrat.core.errors.DependencyError` when they cannot answer.
    """

    def get(self, agent_id: str) -> AgentRecord | None:
        """Return the agent registered under ``agent_id``, or ``None``."""
        ...

    def by_client_id(self, client_id: str) -> AgentRecord | None:
        """Return the agent registered with OAuth ``client_id``, or ``None``."""
        ...


class InMemoryAgentStore:
    """An immutable store built from records held in memory.

    Also satisfies ``pytrat.policy``'s ``AgentDirectory`` protocol via :meth:`is_registered`.
    """

    __slots__ = ("_by_client", "_by_id")

    def __init__(
        self, records: Iterable[AgentRecord], *, ordering: AssuranceOrdering | None = None
    ) -> None:
        """Index ``records``.

        Raises:
            ConfigurationError: On duplicate ids or client ids, or an assurance level that is not
                part of ``ordering`` (default: :class:`AssuranceOrdering` defaults).
        """
        levels = ordering or AssuranceOrdering()
        by_id: dict[str, AgentRecord] = {}
        by_client: dict[str, AgentRecord] = {}
        for record in records:
            # agent-profile-03 §3.6.2: the level feeds min_assurance_level, so it must be known.
            levels.require_known(record.assurance_level)
            if record.id in by_id:
                raise ConfigurationError("duplicate agent id in agent store")
            by_id[record.id] = record
            if record.client_id is not None:
                if record.client_id in by_client:
                    raise ConfigurationError("duplicate client_id in agent store")
                by_client[record.client_id] = record
        self._by_id: Mapping[str, AgentRecord] = MappingProxyType(by_id)
        self._by_client: Mapping[str, AgentRecord] = MappingProxyType(by_client)

    def get(self, agent_id: str) -> AgentRecord | None:
        """Return the agent registered under ``agent_id``, or ``None``."""
        return self._by_id.get(agent_id)

    def by_client_id(self, client_id: str) -> AgentRecord | None:
        """Return the agent registered with ``client_id``, or ``None``."""
        return self._by_client.get(client_id)

    def is_registered(self, agent_id: str) -> bool:
        """Return True if ``agent_id`` is a registered agent."""
        return agent_id in self._by_id

    def __len__(self) -> int:
        return len(self._by_id)


# ---------------------------------------------------------------- YAML

_Text = Annotated[str, StringConstraints(min_length=1, max_length=2048)]


class _YamlAgent(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True, hide_input_in_errors=True)

    id: _Text
    name: _Text
    owner: _Text
    assurance_level: _Text
    version: _Text
    provenance: _Text
    client_id: _Text | None = None
    attributes: dict[str, str] = {}


class _YamlDocument(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True, hide_input_in_errors=True)

    agents: list[_YamlAgent]


class YamlAgentStore(InMemoryAgentStore):
    """An immutable store loaded once from a YAML document.

    Format::

        agents:
          - id: billing-agent
            name: Billing agent
            owner: payments-team
            assurance_level: high
            version: 2.4.1
            provenance: sha256:...
            client_id: billing-agent-client   # optional
            attributes: {tee: sgx}            # optional, string values only
    """

    __slots__ = ()

    def __init__(self, path: str | Path, *, ordering: AssuranceOrdering | None = None) -> None:
        """Load and validate the YAML file at ``path``.

        Raises:
            DependencyError: ``DEPENDENCY_UNAVAILABLE`` if the file cannot be read.
            ConfigurationError: If the document is not valid YAML, does not match the schema
                (strict, unknown keys rejected), or names an unknown assurance level.
        """
        try:
            raw_text = Path(path).read_text(encoding="utf-8")
        except UnicodeDecodeError:
            raise ConfigurationError("agent store file is not valid UTF-8") from None
        except OSError as exc:
            raise DependencyError("agent store file could not be read") from exc
        super().__init__(_parse_yaml(raw_text), ordering=ordering)


def _parse_yaml(raw_text: str) -> list[AgentRecord]:
    try:
        raw_document = yaml.safe_load(raw_text)
    except (yaml.YAMLError, ValueError, RecursionError):
        # PyYAML's constructors raise plain ValueError for values such as 2001-13-14, and deep
        # nesting exhausts its recursive composer.
        raise ConfigurationError("agent store file is not valid YAML") from None
    try:
        document = _YamlDocument.model_validate(raw_document)
    except ValidationError as exc:
        first = exc.errors(include_input=False, include_url=False)[0]
        where = ".".join(str(part) for part in first["loc"]) or "document"
        raise ConfigurationError(f"agent store entry '{where}' is invalid") from None
    return [
        AgentRecord(
            id=agent.id,
            name=agent.name,
            owner=agent.owner,
            assurance_level=agent.assurance_level,
            version=agent.version,
            provenance=agent.provenance,
            attributes=agent.attributes,
            client_id=agent.client_id,
        )
        for agent in document.agents
    ]


# ---------------------------------------------------------------- SQLite

#: Schema expected by :class:`SqliteAgentStore`. ``attributes`` is a JSON object of strings.
SQLITE_SCHEMA: Final = """
CREATE TABLE agents (
    id              TEXT PRIMARY KEY NOT NULL,
    name            TEXT NOT NULL,
    owner           TEXT NOT NULL,
    assurance_level TEXT NOT NULL,
    version         TEXT NOT NULL,
    provenance      TEXT NOT NULL,
    client_id       TEXT UNIQUE,
    attributes      TEXT NOT NULL DEFAULT '{}'
)
"""

_COLUMNS: Final = "id, name, owner, assurance_level, version, provenance, client_id, attributes"
_SELECT_BY_ID: Final = f"SELECT {_COLUMNS} FROM agents WHERE id = ?"  # noqa: S608 - constant
_SELECT_BY_CLIENT: Final = f"SELECT {_COLUMNS} FROM agents WHERE client_id = ?"  # noqa: S608


class SqliteAgentStore:
    """A read-only store backed by an SQLite database (schema: :data:`SQLITE_SCHEMA`).

    The database is opened read-only (``mode=ro``) for each lookup, so the process cannot modify
    it and lookups are safe from any thread. Queries are parametrised. Rows are validated on every
    read: a malformed row or an unknown assurance level is a store-integrity failure and raises
    ``DEPENDENCY_UNAVAILABLE`` (deny), never "not registered".
    """

    __slots__ = ("_ordering", "_uri")

    def __init__(self, path: str | Path, *, ordering: AssuranceOrdering | None = None) -> None:
        """Configure the store. The database is not opened until the first lookup."""
        self._uri = f"{Path(path).resolve().as_uri()}?mode=ro"
        self._ordering = ordering or AssuranceOrdering()

    def get(self, agent_id: str) -> AgentRecord | None:
        """Return the agent registered under ``agent_id``, or ``None``.

        Raises:
            DependencyError: ``DEPENDENCY_UNAVAILABLE`` if the database cannot be queried or the
                row is invalid.
        """
        return self._query_one(_SELECT_BY_ID, agent_id)

    def by_client_id(self, client_id: str) -> AgentRecord | None:
        """Return the agent registered with ``client_id``, or ``None``.

        Raises:
            DependencyError: ``DEPENDENCY_UNAVAILABLE`` if the database cannot be queried, the row
                is invalid, or more than one agent claims ``client_id``.
        """
        return self._query_one(_SELECT_BY_CLIENT, client_id)

    def is_registered(self, agent_id: str) -> bool:
        """Return True if ``agent_id`` is a registered agent.

        Raises:
            DependencyError: As :meth:`get`.
        """
        return self.get(agent_id) is not None

    def _query_one(self, sql: str, key: str) -> AgentRecord | None:
        try:
            with closing(sqlite3.connect(self._uri, uri=True)) as connection:
                rows = connection.execute(sql, (key,)).fetchmany(2)
        except sqlite3.Error as exc:
            raise DependencyError("agent store query failed") from exc
        if not rows:
            return None
        if len(rows) > 1:
            raise DependencyError("agent store returned an ambiguous result")
        return self._to_record(rows[0])

    def _to_record(self, row: tuple[object, ...]) -> AgentRecord:
        agent_id, name, owner, level, version, provenance, client_id, raw_attributes = row
        texts = (agent_id, name, owner, level, version, provenance)
        if not all(isinstance(value, str) and value for value in texts):
            raise DependencyError("agent store row is invalid")
        if client_id is not None and not isinstance(client_id, str):
            raise DependencyError("agent store row is invalid")
        if not self._ordering.is_known(str(level)):
            raise DependencyError("agent store row has an unknown assurance level")
        return AgentRecord(
            id=str(agent_id),
            name=str(name),
            owner=str(owner),
            assurance_level=str(level),
            version=str(version),
            provenance=str(provenance),
            attributes=_parse_attributes(raw_attributes),
            client_id=client_id or None,
        )


def _parse_attributes(raw_attributes: object) -> Mapping[str, str]:
    if not isinstance(raw_attributes, str):
        raise DependencyError("agent store row is invalid")
    try:
        parsed = json.loads(raw_attributes)
    except ValueError as exc:
        raise DependencyError("agent store row is invalid") from exc
    if not isinstance(parsed, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in parsed.items()
    ):
        raise DependencyError("agent store row is invalid")
    return parsed
