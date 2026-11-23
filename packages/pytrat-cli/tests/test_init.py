"""``pytrat init``: the starter project it writes must be safe and must actually work."""

from __future__ import annotations

import json
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from pytrat.cli import app
from pytrat.cli._starter import planned_files
from pytrat.core import StaticKeySet
from pytrat.core.crypto import load_private_key_pem
from pytrat.server import load_settings

runner = CliRunner()


@pytest.fixture
def project(tmp_path: Path) -> Path:
    directory = tmp_path / "starter"
    result = runner.invoke(app, ["init", str(directory), "--trust-domain", "shop.internal"])
    assert result.exit_code == 0, result.output
    return directory


def test_writes_every_planned_file(project: Path) -> None:
    for path in planned_files(project):
        assert path.is_file(), path


def test_private_keys_are_0600_and_git_ignored(project: Path) -> None:
    for name in ("tts", "gateway"):
        pem = project / "keys" / f"{name}.pem"
        assert stat.S_IMODE(pem.stat().st_mode) == 0o600
        load_private_key_pem(pem.read_bytes())
    assert "keys/*.pem" in (project / ".gitignore").read_text(encoding="utf-8")


def test_published_jwks_hold_no_private_material(project: Path) -> None:
    for name in ("tts", "gateway"):
        jwks = json.loads((project / "keys" / f"{name}.jwks.json").read_text(encoding="utf-8"))
        [key] = jwks["keys"]
        assert "d" not in key
        assert key["kid"] == name
        assert StaticKeySet.from_jwks(jwks).get(name) is not None


def test_trust_domain_is_applied_everywhere(project: Path) -> None:
    for name in ("service.py", "gateway.py", "tts.yaml", "README.md"):
        text = (project / name).read_text(encoding="utf-8")
        assert "__TRUST_DOMAIN__" not in text, name
        assert "shop.internal" in text, name


def test_tts_config_is_valid_for_the_reference_tts(project: Path) -> None:
    settings = load_settings(project / "tts.yaml")
    assert settings.trust_domain == "shop.internal"


def test_existing_project_is_not_overwritten(project: Path) -> None:
    pem = project / "keys" / "tts.pem"
    before = pem.read_bytes()
    result = runner.invoke(app, ["init", str(project)])
    assert result.exit_code == 1
    assert "--force" in result.output
    assert pem.read_bytes() == before


def test_force_regenerates_keys(project: Path) -> None:
    pem = project / "keys" / "tts.pem"
    before = pem.read_bytes()
    result = runner.invoke(app, ["init", str(project), "--force"])
    assert result.exit_code == 0, result.output
    assert pem.read_bytes() != before
    assert stat.S_IMODE(pem.stat().st_mode) == 0o600


@pytest.mark.parametrize("trust_domain", ["", "has space", 'quote"d', "back\\slash"])
def test_unsafe_trust_domain_is_refused(tmp_path: Path, trust_domain: str) -> None:
    result = runner.invoke(app, ["init", str(tmp_path / "p"), "--trust-domain", trust_domain])
    assert result.exit_code == 1
    assert not (tmp_path / "p").exists()


def test_generated_tests_pass(project: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-W", "ignore"],
        cwd=project,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "5 passed" in result.stdout
