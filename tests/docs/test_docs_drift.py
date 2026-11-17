"""Reference pages must match the code they describe.

The tables in the TTS, policy, Django and CLI guides are written by hand (they carry explanations
the code does not), so these tests compare them with the models and the Typer application in both
directions: every key exists in the docs with its real default, and every documented key exists.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path
from types import ModuleType

import pytest
import typer.main

from pytrat.cli import app as cli
from pytrat.core import ReasonCode
from pytrat.policy import PolicyDocument
from pytrat.server import TtsSettings, load_settings

from ._reference import documented_rows, fields
from .conftest import DOCS, REPO

GUIDES = DOCS / "guides"


def _hook() -> ModuleType:
    spec = importlib.util.spec_from_file_location("pytrat_docs", DOCS / "hooks" / "pytrat_docs.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_reason_code_table_covers_every_reason_code() -> None:
    hook = _hook()
    hook.check_reason_codes()
    table = hook.reason_code_table()
    assert [line.split("`")[1] for line in table.splitlines()[2:]] == [c.value for c in ReasonCode]
    assert hook.REASON_CODES_MARKER in (GUIDES / "errors.md").read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("model", "page"),
    [(TtsSettings, GUIDES / "tts.md"), (PolicyDocument, GUIDES / "policies.md")],
    ids=["tts-settings", "policy-schema"],
)
def test_reference_table_matches_model(model, page: Path) -> None:
    rows = documented_rows(page)
    keys = list(fields(model))
    leaves = {field.key: field.default for field in keys if field.leaf}
    assert sorted(set(leaves) - set(rows)) == [], "undocumented keys"
    assert sorted(set(rows) - {field.key for field in keys}) == [], (
        "documented keys that do not exist"
    )
    wrong = {key: (rows[key], default) for key, default in leaves.items() if rows[key] != default}
    assert wrong == {}, "documented default (left) differs from the model (right)"


def test_tts_example_configuration_is_valid() -> None:
    settings = load_settings(REPO / "packages" / "pytrat-server" / "examples" / "tts.yaml")
    assert settings.trust_domain == "payments.internal"


def test_django_settings_keys_are_documented() -> None:
    from pytrat.django._settings import _KNOWN_KEYS

    page = (GUIDES / "django.md").read_text(encoding="utf-8")
    documented = set(re.findall(r"^\| `([A-Z_]+)` \|", page, flags=re.MULTILINE))
    assert documented == set(_KNOWN_KEYS)


def test_security_page_includes_the_policy_text_only() -> None:
    # docs/security/policy.md includes SECURITY.md lines 3-11 and writes its own Scope section.
    lines = (REPO / "SECURITY.md").read_text(encoding="utf-8").splitlines()
    assert lines[0] == "# Security policy"
    assert lines[12] == "## Scope"
    assert "](" not in "\n".join(lines[2:11]), "included lines must not carry repo-relative links"


@pytest.mark.parametrize("readme", sorted((REPO / "packages").glob("*/README.md")), ids=str)
def test_package_readme_examples_parse_and_import_public_names(readme: Path) -> None:
    import ast
    import importlib

    blocks = re.findall(r"```python\n(.*?)```", readme.read_text(encoding="utf-8"), re.S)
    for block in blocks:
        tree = ast.parse(block)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("pytrat."):
                module = importlib.import_module(node.module or "")
                public = set(getattr(module, "__all__", dir(module)))
                missing = [alias.name for alias in node.names if alias.name not in public]
                assert missing == [], f"{readme}: {node.module} has no public {missing}"


def _commands() -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}

    def walk(command: object, path: list[str]) -> None:
        subcommands = getattr(command, "commands", None)
        if subcommands:
            for name, sub in subcommands.items():
                walk(sub, [*path, name])
            return
        options: list[str] = []
        for param in command.params:  # type: ignore[attr-defined]
            opts = list(getattr(param, "opts", []))
            if opts and opts[0].startswith("-"):
                options.extend([*opts, *getattr(param, "secondary_opts", [])])
            else:
                options.append(param.name.upper())
        found[" ".join(path)] = options

    walk(typer.main.get_command(cli), ["pytrat"])
    return found


def test_cli_reference_covers_every_command_and_option() -> None:
    page = (GUIDES / "cli.md").read_text(encoding="utf-8")
    sections = dict(re.findall(r"^### `(pytrat[^`]*)`\n(.*?)(?=^### |\Z)", page, re.M | re.S))
    commands = _commands()
    assert sorted(sections) == sorted(commands)
    for command, options in commands.items():
        missing = [opt for opt in options if f"`{opt}`" not in sections[command]]
        assert missing == [], f"{command}: undocumented {missing}"
