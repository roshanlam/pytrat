"""``pytrat init``: write a runnable starter project (keys, TTS config, service, tests, caller).

Private: the generated files are documentation for the user, not API.
"""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path

from pytrat.core import StaticKeySet, VerificationKey
from pytrat.core.crypto import generate_private_key, private_key_to_pem

ALG = "ES256"
KEY_NAMES = ("tts", "gateway")
_TEMPLATES = ("README.md", "service.py", "test_service.py", "gateway.py", "tts.yaml")
_GITIGNORE = "# Private keys never leave this machine.\nkeys/*.pem\n__pycache__/\n"
_PLACEHOLDER = "__TRUST_DOMAIN__"


@dataclass(frozen=True, slots=True)
class StarterProject:
    """What :func:`write_starter` produced."""

    directory: Path
    files: Sequence[Path]


def planned_files(directory: Path) -> list[Path]:
    """Every file :func:`write_starter` writes into ``directory``."""
    keys = [
        directory / "keys" / f"{name}{suffix}"
        for name in KEY_NAMES
        for suffix in (".pem", ".jwks.json")
    ]
    return [*(directory / name for name in (*_TEMPLATES, ".gitignore")), *keys]


def existing_files(directory: Path) -> list[Path]:
    """The files :func:`write_starter` would overwrite in ``directory``."""
    return [path for path in planned_files(directory) if path.exists()]


def write_starter(directory: Path, *, trust_domain: str) -> StarterProject:
    """Generate fresh development keys and the starter files into ``directory``.

    Overwrites any file listed by :func:`existing_files`; callers decide whether that is allowed.
    """
    planned = planned_files(directory)
    (directory / "keys").mkdir(parents=True, exist_ok=True)
    for name in _TEMPLATES:
        template = files(__package__).joinpath("templates", f"{name}.tmpl").read_text("utf-8")
        (directory / name).write_text(template.replace(_PLACEHOLDER, trust_domain), "utf-8")
    (directory / ".gitignore").write_text(_GITIGNORE, "utf-8")
    for name in KEY_NAMES:
        _write_key(directory / "keys", name)
    return StarterProject(directory=directory, files=planned)


def _write_key(keys_dir: Path, name: str) -> None:
    private_key = generate_private_key(ALG)
    pem = keys_dir / f"{name}.pem"
    descriptor = os.open(pem, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(descriptor, 0o600)  # O_CREAT's mode does not apply to a file that already exists
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(private_key_to_pem(private_key))
    public = VerificationKey.from_public_key(name, private_key.public_key(), ALG)
    (keys_dir / f"{name}.jwks.json").write_text(StaticKeySet([public]).to_json() + "\n", "utf-8")
