"""The payment-transfer demo deployed with Docker Compose, every hop over verified TLS.

Slow and needs a Docker daemon, so it runs only with ``PYTRAT_TEST_COMPOSE=1``:

    PYTRAT_TEST_COMPOSE=1 uv run pytest tests/integration/test_payment_compose.py -q
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

SMOKE = Path(__file__).parents[2] / "examples" / "payment-transfer" / "compose" / "smoke.py"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("PYTRAT_TEST_COMPOSE") != "1", reason="set PYTRAT_TEST_COMPOSE=1 to run"
    ),
    pytest.mark.skipif(shutil.which("docker") is None, reason="docker is not installed"),
]


def test_compose_deployment_records_honest_transfer_and_refuses_tampered_one() -> None:
    """Honest transfer → 201; compromised payment service's $9,000 → 403 at the ledger."""
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, str(SMOKE)],
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    assert result.returncode == 0, result.stdout[-4000:] + result.stderr[-4000:]
    assert "PASS" in result.stdout
