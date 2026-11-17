"""PyTraT demo: a $100 transfer, then a compromised service tries to make it $9,000.

Run from the repository root:

    uv run python examples/payment-transfer/demo.py

Four services (gateway, payment, ledger and the reference TTS) run in-process over real HTTP
semantics via ASGI. Keys are generated fresh into a temporary directory.
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from payment_demo.scenario import TRANSFER, deploy, render

BOLD, GREEN, RED, DIM, RESET = "\033[1m", "\033[32m", "\033[31m", "\033[2m", "\033[0m"


def heading(text: str) -> None:
    print(f"\n{BOLD}{text}{RESET}")


async def run_scenario(work_dir: Path, *, compromised: bool) -> bool:
    label = "compromised payment service" if compromised else "honest services"
    heading(f"── Transfer $100.00 from account-A to account-B ({label})")
    async with deploy(work_dir, compromised=compromised) as deployment:
        response = await deployment.transfer(TRANSFER)
        body = response.json()
        if response.status_code == 201:
            entry = body["entry"]
            print(
                f"{GREEN}✔ {response.status_code} recorded{RESET}: "
                f"{entry['amount_minor'] / 100:.2f} {entry['currency']} "
                f"(txn {entry['transaction_id']})"
            )
        else:
            reason, title = body.get("reason_code"), body.get("title")
            print(f"{RED}✘ {response.status_code} {reason}{RESET}: {title}")
        print(f"{DIM}ledger entries recorded: {len(deployment.ledger_entries)}{RESET}")
        denials = [e for e in deployment.audit["ledger-service"].events if e.reason_code]
        for event in denials:
            heading("Ledger audit event")
            print(render(event.to_json()))
        return response.status_code == 201


async def main() -> int:
    with tempfile.TemporaryDirectory(prefix="pytrat-demo-") as tmp:
        ok = await run_scenario(Path(tmp) / "honest", compromised=False)
        blocked = not await run_scenario(Path(tmp) / "compromised", compromised=True)
    heading("Result")
    print(f"legitimate transfer succeeded: {ok}")
    print(f"tampered transfer blocked:     {blocked}")
    return 0 if ok and blocked else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
