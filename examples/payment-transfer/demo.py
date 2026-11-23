"""PyTraT demo: a $100 transfer, then a compromised service tries to make it $9,000.

The same story as ``pytrat demo`` (after ``pip install "pytrat[all]"``). From the repository root:

    uv run python examples/payment-transfer/demo.py

Four services (gateway, payment, ledger and the reference TTS) run in-process over real HTTP
semantics via ASGI. Keys are generated fresh into a temporary directory. The services live in
``packages/pytrat-cli/src/pytrat/cli/_demo/services.py``.
"""

from __future__ import annotations

import asyncio

from pytrat.cli._demo.narrative import run_demo

if __name__ == "__main__":
    raise SystemExit(0 if asyncio.run(run_demo()) else 1)
