"""Replay every Atheris seed corpus through its harness under plain pytest.

The harnesses in ``fuzz/`` run coverage-guided under Atheris (Linux x86-64 only, see
``fuzz/README.md``). Their ``TestOneInput`` functions have no Atheris dependency, so this suite
runs every committed seed — including regression inputs for bugs the fuzzer found — on every
Python version in CI. A harness raises on any invariant violation or unexpected exception type.
"""

from __future__ import annotations

import importlib
from types import ModuleType

import pytest

from fuzz._harness import CORPUS_DIR, harness_names
from fuzz.make_corpus import target_name

pytestmark = pytest.mark.security

HARNESSES = harness_names()


def _harness(module_name: str) -> ModuleType:
    return importlib.import_module(f"fuzz.{module_name}")


def _corpus() -> list[tuple[str, str]]:
    return [
        (module_name, seed.name)
        for module_name in HARNESSES
        for seed in sorted((CORPUS_DIR / target_name(module_name)).iterdir())
    ]


def test_every_harness_has_a_seed_corpus() -> None:
    for module_name in HARNESSES:
        directory = CORPUS_DIR / target_name(module_name)
        assert directory.is_dir(), f"run `python -m fuzz.make_corpus` ({module_name})"
        assert any(directory.iterdir()), module_name


@pytest.mark.parametrize("module_name", HARNESSES)
def test_committed_corpus_matches_the_harness_seeds(module_name: str) -> None:
    """Generated seeds are deterministic except for freshly generated public keys."""
    directory = CORPUS_DIR / target_name(module_name)
    assert len(list(_harness(module_name).seeds())) == len(list(directory.iterdir()))


@pytest.mark.parametrize(("module_name", "seed"), _corpus())
def test_seed_replays_cleanly(module_name: str, seed: str) -> None:
    data = (CORPUS_DIR / target_name(module_name) / seed).read_bytes()
    _harness(module_name).TestOneInput(data)


@pytest.mark.parametrize("module_name", HARNESSES)
def test_generated_seeds_replay_cleanly(module_name: str) -> None:
    """Seeds as generated now, so keys created at import time are exercised too."""
    harness = _harness(module_name)
    for data in harness.seeds():
        harness.TestOneInput(data)
