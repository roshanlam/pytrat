"""Fuzz the YAML Agent Attribute Store loader (``YamlAgentStore``).

Invariants: any file content either loads or raises :class:`ConfigurationError`; every loaded
record has an assurance level from the configured ordering and resolves by its id.
"""

from __future__ import annotations

import tempfile
from collections.abc import Iterator
from functools import cache
from pathlib import Path

from fuzz._harness import fuzz
from pytrat.agents import YamlAgentStore
from pytrat.core import DEFAULT_LEVELS, AssuranceOrdering, ConfigurationError

_ORDERING = AssuranceOrdering(DEFAULT_LEVELS)

_VALID = b"""\
agents:
  - id: billing-agent
    name: Billing agent
    owner: payments-team
    assurance_level: high
    version: 2.4.1
    provenance: sha256:0000
    client_id: billing-client
    attributes: {tee: sgx}
  - id: planner
    name: Planner
    owner: ai-team
    assurance_level: low
    version: "1"
    provenance: build-1
"""


@cache
def _registry_file() -> Path:
    # One scratch file for the whole run; the loader only accepts a path.
    directory = Path(tempfile.mkdtemp(prefix="pytrat-fuzz-"))
    return directory / "agents.yaml"


def TestOneInput(data: bytes) -> None:  # noqa: N802 - name required by Atheris
    """Write ``data`` as the registry file and load it."""
    path = _registry_file()
    path.write_bytes(data)
    try:
        store = YamlAgentStore(path, ordering=_ORDERING)
    except ConfigurationError:
        return
    for record_id in [record.id for record in store._by_id.values()]:
        record = store.get(record_id)
        if record is None or record.assurance_level not in _ORDERING.levels:
            raise AssertionError("a loaded agent record is unresolvable or has an unknown level")


def seeds() -> Iterator[bytes]:
    """A valid registry and malformed variations."""
    yield _VALID
    yield _VALID.replace(b"level: low", b"level: ultra")
    yield _VALID.replace(b"id: planner", b"id: billing-agent")
    yield _VALID.replace(b"client_id: billing-client", b"client_id: 5")
    yield _VALID.replace(b"version: 2.4.1", b"version: 2001-13-14")
    yield b"agents: []\n"
    yield b"agents: [1]\n"
    # Regression: undecodable bytes, constructor errors and deep nesting escaped as
    # UnicodeDecodeError / ValueError / RecursionError.
    yield b"\xff\xfe"
    yield b"agents: [!!int 0x]\n"
    yield b"[" * 700 + b"]" * 700
    yield b"agents: " + b"[" * 32 + b"]" * 32


if __name__ == "__main__":
    fuzz(TestOneInput)
