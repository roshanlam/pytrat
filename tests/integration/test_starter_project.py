"""The project ``pytrat init`` writes, run as its README says: TTS, service and gateway.

The TTS and the service run under uvicorn on free loopback ports; the generated ``gateway.py``
obtains a token and sends an honest and a tampered order.
"""

from __future__ import annotations

import asyncio
import importlib.util
import socket
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
import uvicorn
from fastapi import FastAPI
from typer.testing import CliRunner

from pytrat.cli import app as cli
from pytrat.server import create_app_from_settings

pytestmark = pytest.mark.integration


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
        return port


@asynccontextmanager
async def _serving(apps: dict[int, FastAPI]) -> AsyncIterator[None]:
    servers = [
        uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
        for port, app in apps.items()
    ]
    tasks = [asyncio.create_task(server.serve()) for server in servers]
    try:
        while not all(server.started for server in servers):
            await asyncio.sleep(0.01)
        yield
    finally:
        for server in servers:
            server.should_exit = True
        await asyncio.gather(*tasks)


def _load(path: Path, name: str) -> object:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


async def test_gateway_gets_201_for_the_order_and_403_for_the_tampered_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    project = tmp_path / "starter"
    assert CliRunner().invoke(cli, ["init", str(project)]).exit_code == 0
    tts_port, service_port = _free_port(), _free_port()
    for name in ("tts.yaml", "gateway.py"):
        path = project / name
        text = path.read_text(encoding="utf-8")
        text = text.replace("127.0.0.1:8080", f"127.0.0.1:{tts_port}")
        path.write_text(text.replace("127.0.0.1:8000", f"127.0.0.1:{service_port}"), "utf-8")

    service = _load(project / "service.py", "starter_service")
    gateway = _load(project / "gateway.py", "starter_gateway")
    apps = {
        tts_port: create_app_from_settings(project / "tts.yaml"),
        service_port: service.app(),  # type: ignore[attr-defined]
    }
    try:
        async with _serving(apps):
            await asyncio.to_thread(gateway.main)  # type: ignore[attr-defined]
    finally:
        sys.modules.pop("starter_service", None)
        sys.modules.pop("starter_gateway", None)

    output = capsys.readouterr().out
    assert "order as authorized    -> 201" in output
    assert "quantity changed to 500 -> 403" in output
    assert "TRANSACTION_CONTEXT_MISMATCH" in output
