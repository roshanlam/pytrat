"""Execute every code snippet the documentation includes."""

from __future__ import annotations

from pathlib import Path

import httpx
from typer.testing import CliRunner

from pytrat.cli import app as cli

runner = CliRunner()


async def test_getting_started_try_it_test_passes(snippet, tmp_path: Path) -> None:
    module = snippet("try_first_route")
    await module.test_ledger_records_only_the_authorized_transfer(tmp_path)


async def test_getting_started_production_app_uses_cli_generated_keys(
    snippet, tmp_path: Path
) -> None:
    keys = tmp_path / "keys"
    for kid in ("tts-2026-11", "payment-service"):
        result = runner.invoke(cli, ["keys", "generate", "--kid", kid, "--out", str(keys)])
        assert result.exit_code == 0, result.output
    app = snippet("first_route").production_app(keys)
    transport = httpx.ASGITransport(app=app)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="https://ledger.internal") as client,
    ):
        response = await client.post("/internal/ledger/entries", json={})
    assert response.status_code == 401
    assert response.json()["reason_code"] == "TOKEN_MISSING"
