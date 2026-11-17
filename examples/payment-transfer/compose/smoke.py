"""Docker Compose smoke test: honest $100 transfer, then the compromised payment service's $9,000.

    python examples/payment-transfer/compose/smoke.py           # build, run, assert, tear down
    python examples/payment-transfer/compose/smoke.py --keep    # leave the stack running

Standard library only, so it runs on any host with Docker. Exits 0 only if the honest transfer is
recorded (201) and the tampered one is refused (403 TRANSACTION_CONTEXT_MISMATCH) with a matching
``authorization.denied`` audit event from the ledger.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

COMPOSE_DIR = Path(__file__).resolve().parent
EXPECTED_REASON = "TRANSACTION_CONTEXT_MISMATCH"


def compose(
    *args: str, compromised: bool = False, capture: bool = False
) -> subprocess.CompletedProcess[str]:
    """Run ``docker compose`` in this directory; raise if it fails.

    ``PYTRAT_DEMO_COMPROMISED`` is passed explicitly on every call: compose recreates services
    whose resolved configuration differs, so a call without it would swap the honest payment
    service back in.
    """
    docker = shutil.which("docker")
    if docker is None:
        raise SystemExit("docker is not installed")
    env = {**os.environ, "PYTRAT_DEMO_COMPROMISED": "1" if compromised else "0"}
    print(f"$ {'PYTRAT_DEMO_COMPROMISED=1 ' if compromised else ''}docker compose {' '.join(args)}")
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [docker, "compose", *args],
        cwd=COMPOSE_DIR,
        env=env,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
    )


def transfer(*, compromised: bool) -> Mapping[str, object]:
    """Run the client container once; return its ``{"status": ..., "body": ...}`` result."""
    result = compose("run", "--rm", "client", compromised=compromised, capture=True)
    outcome: Mapping[str, object] = json.loads(result.stdout.strip().splitlines()[-1])
    print(json.dumps(outcome, indent=2))
    return outcome


def audit_events(service: str) -> list[Mapping[str, object]]:
    """The JSON audit events a service logged to stdout."""
    logs = compose("logs", "--no-log-prefix", "--no-color", service, capture=True).stdout
    return [json.loads(line) for line in logs.splitlines() if line.startswith("{")]


def check(failures: list[str], condition: bool, message: str) -> None:
    """Record ``message`` as a failure unless ``condition`` holds."""
    print(f"{'ok  ' if condition else 'FAIL'} {message}")
    if not condition:
        failures.append(message)


def run(*, build: bool) -> list[str]:
    """Bring the stack up, run both scenarios, return the failed checks."""
    failures: list[str] = []
    compose("up", *(["--build"] if build else []), "-d", "--wait")

    print("\n== honest services: transfer $100.00")
    honest = transfer(compromised=False)
    check(failures, honest["status"] == 201, "honest transfer is recorded (201)")

    print("\n== compromised payment service rewrites the amount to $9,000.00")
    compose("up", "-d", "--wait", "payment", compromised=True)
    tampered = transfer(compromised=True)
    body = tampered["body"]
    reason = body.get("reason_code") if isinstance(body, dict) else None
    check(failures, tampered["status"] == 403, "tampered transfer is refused (403)")
    check(failures, reason == EXPECTED_REASON, f"reason code is {EXPECTED_REASON}")

    print("\n== ledger audit event")
    denials = [e for e in audit_events("ledger") if e.get("event_type") == "authorization.denied"]
    for event in denials:
        print(json.dumps(event, indent=2, sort_keys=True))
    check(
        failures,
        len(denials) == 1 and denials[0].get("reason_code") == EXPECTED_REASON,
        "ledger logged exactly one authorization.denied event with that reason",
    )
    return failures


def main(argv: Sequence[str] | None = None) -> int:
    """Run the smoke test; tear the stack down (volumes included) unless ``--keep``."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", action="store_true", help="leave the stack running")
    parser.add_argument("--no-build", action="store_true", help="reuse the existing image")
    args = parser.parse_args(argv)
    try:
        failures = run(build=not args.no_build)
    finally:
        if not args.keep:
            compose("down", "-v", "--remove-orphans")
    print("\nPASS" if not failures else f"\nFAILED: {failures}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
