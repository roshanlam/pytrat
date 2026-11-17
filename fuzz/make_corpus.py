"""Regenerate the seed corpora: ``fuzz/corpus/<target>/`` from each harness's ``seeds()``.

Run from the repository root::

    uv run python -m fuzz.make_corpus

Seeds never contain private keys or valid tokens: any key a seed needs (a public JWK) is
generated on the spot, and signed inputs are signed by the harness at fuzz time.
"""

from __future__ import annotations

import hashlib
import importlib
import logging
import shutil

from fuzz._harness import CORPUS_DIR, harness_names

_logger = logging.getLogger(__name__)


def target_name(module_name: str) -> str:
    """The corpus directory name of a harness module (``fuzz_jwks`` → ``jwks``)."""
    return module_name.removeprefix("fuzz_")


def main() -> None:
    """Rewrite every corpus directory from scratch."""
    for module_name in harness_names():
        module = importlib.import_module(f"fuzz.{module_name}")
        directory = CORPUS_DIR / target_name(module_name)
        shutil.rmtree(directory, ignore_errors=True)
        directory.mkdir(parents=True)
        count = 0
        for seed in module.seeds():
            (directory / hashlib.sha256(seed).hexdigest()[:16]).write_bytes(seed)
            count += 1
        _logger.warning("%s: %d seeds", directory.name, count)


if __name__ == "__main__":
    logging.basicConfig(format="%(message)s")
    main()
