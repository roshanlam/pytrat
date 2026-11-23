"""Narrate the demo: a $100 transfer, then a compromised service tries to make it $9,000."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import typer

from pytrat.cli._demo.scenario import TRANSFER, deploy

_STORY = """\
A user asks the API gateway to move $100.00 from account-A to account-B. The gateway gets a
Transaction Token from the Transaction Token Service (TTS) that records exactly that transfer,
then calls payment-service, which calls ledger-service. Every service verifies the token.

  user -> api-gateway -> payment-service -> ledger-service
               |
               +-> TTS (signs the Transaction Token)
"""

_MORAL = """\
The attacker controlled payment-service completely and could rewrite the request it forwarded,
but it holds no signing key, so it could not change what the token authorized. The ledger
compared the request with the token, refused it, and recorded why.

Protect your own routes: https://github.com/roshanlam/pytrat/blob/main/docs/getting-started.md
"""


async def run_demo(*, show_audit: bool = True) -> bool:
    """Run both scenarios and narrate them.

    Args:
        show_audit: Print the ledger's audit event for the refused transfer.

    Returns:
        True when the honest transfer was recorded and the tampered one was refused.
    """
    typer.echo(_STORY)
    with tempfile.TemporaryDirectory(prefix="pytrat-demo-") as tmp:
        recorded = await _scenario(Path(tmp) / "honest", compromised=False, show_audit=False)
        refused = not await _scenario(
            Path(tmp) / "compromised", compromised=True, show_audit=show_audit
        )
    _heading("Result")
    _check(recorded, "the legitimate $100.00 transfer was recorded")
    _check(refused, "the tampered $9,000.00 transfer was refused")
    if recorded and refused:
        typer.echo("\n" + _MORAL)
    return recorded and refused


async def _scenario(work_dir: Path, *, compromised: bool, show_audit: bool) -> bool:
    if compromised:
        _heading("2. payment-service is compromised and rewrites $100.00 to $9,000.00")
    else:
        _heading("1. Every service is honest")
    async with deploy(work_dir, compromised=compromised) as deployment:
        response = await deployment.transfer(TRANSFER)
        body = response.json()
        if response.status_code == 201:
            entry = body["entry"]
            amount = f"{entry['amount_minor'] / 100:.2f} {entry['currency']}"
            typer.secho(f"   ledger: {response.status_code} recorded {amount}", fg="green")
        else:
            reason = body.get("reason_code")
            typer.secho(f"   ledger: {response.status_code} refused ({reason})", fg="red")
        typer.echo(f"   ledger entries recorded: {len(deployment.ledger_entries)}")
        if show_audit:
            for event in deployment.audit["ledger-service"].events:
                if event.reason_code:
                    typer.secho("\n   ledger audit event:", dim=True)
                    rendered = json.dumps(json.loads(event.to_json()), indent=2, sort_keys=True)
                    typer.secho(_indent(rendered), dim=True)
        return response.status_code == 201


def _heading(text: str) -> None:
    typer.secho(f"\n{text}", bold=True)


def _check(ok: bool, text: str) -> None:
    mark, colour = ("✔", "green") if ok else ("✘", "red")
    typer.secho(f"   {mark} {text}", fg=colour)


def _indent(text: str) -> str:
    return "\n".join(f"   {line}" for line in text.splitlines())
