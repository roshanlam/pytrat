"""Shared helpers for the documentation tests.

The code in ``docs/snippets`` is included verbatim in the published pages (``pymdownx.snippets``),
type-checked by ``uv run mypy`` and executed here, so a documented example cannot rot.
"""

from __future__ import annotations

import importlib
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from types import ModuleType

import pytest

REPO = Path(__file__).resolve().parents[2]
DOCS = REPO / "docs"
SNIPPETS = DOCS / "snippets"


@pytest.fixture
def snippet(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[[str], ModuleType]]:
    """Import a module from ``docs/snippets`` by name, freshly for each test."""
    monkeypatch.syspath_prepend(str(SNIPPETS))
    before = set(sys.modules)

    def load(name: str) -> ModuleType:
        return importlib.import_module(name)

    yield load
    # Forget every snippet module imported during the test (including transitive ones).
    for name in set(sys.modules) - before:
        module_file = getattr(sys.modules[name], "__file__", None) or ""
        if module_file.startswith(str(SNIPPETS)):
            del sys.modules[name]
