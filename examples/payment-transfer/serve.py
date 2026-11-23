"""Run the demo over real TCP sockets: four uvicorn servers on 127.0.0.1.

    uv run python examples/payment-transfer/serve.py               # run both scenarios and exit
    uv run python examples/payment-transfer/serve.py --keep-running  # leave the stack up for curl

Plain HTTP is permitted only because every service is on loopback (PyTraT refuses http:// for any
other host). In production, run each service behind TLS.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import tempfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import uvicorn
from fastapi import FastAPI

sys.path.insert(0, str(Path(__file__).parent))

from pytrat.cli._demo.lab import Lab, Urls
from pytrat.cli._demo.scenario import TRANSFER
from pytrat.cli._demo.services import create_gateway, create_ledger, create_payment, create_tts

PORTS = {"tts": 8701, "gateway": 8702, "payment": 8703, "ledger": 8704}


def local_urls() -> Urls:
    return Urls(**{name: f"http://127.0.0.1:{port}" for name, port in PORTS.items()})


@asynccontextmanager
async def running(apps: dict[str, FastAPI]) -> AsyncIterator[None]:
    servers = [
        uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=PORTS[name], log_level="warning"))
        for name, app in apps.items()
    ]
    tasks = [asyncio.create_task(server.serve()) for server in servers]
    while not all(server.started for server in servers):
        if any(task.done() for task in tasks):
            raise SystemExit("a service failed to start (is a port in use?)")
        await asyncio.sleep(0.05)
    try:
        yield
    finally:
        for server in servers:
            server.should_exit = True
        await asyncio.gather(*tasks)


async def scenario(work_dir: Path, *, compromised: bool, keep_running: bool) -> int:
    lab = Lab.create(work_dir, local_urls())
    apps = {
        "tts": create_tts(lab),
        "gateway": create_gateway(lab),
        "payment": create_payment(lab, compromised=compromised),
        "ledger": create_ledger(lab),
    }
    async with running(apps):
        token = lab.user_access_token().reveal()
        async with httpx.AsyncClient() as user:
            response = await user.post(
                f"{lab.urls.gateway}/transfers",
                json=TRANSFER,
                headers={"Authorization": f"Bearer {token}"},
            )
        label = "compromised" if compromised else "honest"
        print(f"[{label}] {response.status_code} {response.json()}")
        if keep_running:
            print(f"gateway: {lab.urls.gateway}/transfers  (Ctrl-C to stop)")
            await asyncio.Event().wait()
        return response.status_code


async def main(keep_running: bool) -> int:
    with tempfile.TemporaryDirectory(prefix="pytrat-serve-") as tmp:
        honest = await scenario(Path(tmp) / "honest", compromised=False, keep_running=keep_running)
        tampered = await scenario(Path(tmp) / "tampered", compromised=True, keep_running=False)
    return 0 if (honest, tampered) == (201, 403) else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep-running", action="store_true")
    raise SystemExit(asyncio.run(main(parser.parse_args().keep_running)))
