"""A minimal stand-in for Tokenetes' ``tconfigd``, for interoperability tests only.

Runs inside the interop container (see ``Dockerfile``); it is not part of PyTraT and is never
imported by the test suite.

Tokenetes and tokenetes-agent receive *all* of their configuration, and tokenetes-agent receives its
verification keys, over a SPIFFE-mTLS WebSocket from tconfigd (a Kubernetes controller). This mock
speaks the same message protocol, reconstructed from:

* tokenetes ``service/pkg/configsync/configsync.go`` (INITIAL_RULES_RESPONSE, GET_JWKS_REQUEST)
* tokenetes-agent ``service/configsync/configsync.go`` (INITIAL_RULES_RESPONSE, GET_JWKS_REQUEST)
* tconfigd ``service/websocketserver/clientmanager.go`` (JWKS aggregation)

It also exposes a plain-HTTP control API on loopback-published port 8080 for the host test run:

* ``GET  /healthz``       200 once both Tokenetes and tokenetes-agent are connected
* ``GET  /tokenetes-jwks`` the Tokenetes signing JWKS, fetched over the WebSocket
* ``PUT  /extra-jwks``    extra (test) keys that tokenetes-agent will trust in addition
"""

from __future__ import annotations

import asyncio
import json
import os
import ssl
import sys
import uuid
from pathlib import Path
from typing import Any

from websockets.asyncio.server import ServerConnection, serve

SVID_DIR = Path(os.environ.get("TCONFIGD_SVID_DIR", "/run/tconfigd"))
RULES_DIR = Path(os.environ.get("TCONFIGD_RULES_DIR", "/etc/interop/rules"))
TRUST_DOMAIN = os.environ.get("INTEROP_TRUST_DOMAIN", "interop.test")
TOKENETES_ID = f"spiffe://{TRUST_DOMAIN}/tokenetes"
AGENT_ID = f"spiffe://{TRUST_DOMAIN}/tokenetes-agent"

connections: dict[str, ServerConnection] = {}
pending: dict[str, asyncio.Future[dict[str, Any]]] = {}
extra_keys: list[dict[str, Any]] = []


def log(message: str) -> None:
    sys.stderr.write(f"mock-tconfigd: {message}\n")
    sys.stderr.flush()


def tls_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(SVID_DIR / "svid.0.pem", SVID_DIR / "svid.0.key")
    context.load_verify_locations(SVID_DIR / "bundle.0.pem")
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def peer_spiffe_id(websocket: ServerConnection) -> str | None:
    ssl_object = websocket.transport.get_extra_info("ssl_object")
    cert = ssl_object.getpeercert() if ssl_object else None
    for kind, value in (cert or {}).get("subjectAltName", ()):
        if kind == "URI" and value.startswith("spiffe://"):
            return str(value)
    return None


async def request(peer: str, msg_type: str, timeout: float = 10.0) -> dict[str, Any]:
    websocket = connections.get(peer)
    if websocket is None:
        raise LookupError(f"{peer} is not connected")
    request_id = str(uuid.uuid4())
    future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
    pending[request_id] = future
    try:
        await websocket.send(json.dumps({"id": request_id, "type": msg_type}))
        return await asyncio.wait_for(future, timeout)
    finally:
        pending.pop(request_id, None)


async def tokenetes_jwks() -> dict[str, Any]:
    response = await request(TOKENETES_ID, "GET_JWKS_REQUEST")
    if response.get("status") != 200:
        raise RuntimeError(f"tokenetes JWKS status {response.get('status')}")
    payload = response.get("payload")
    return payload if isinstance(payload, dict) else {"keys": []}


async def answer_agent(websocket: ServerConnection, message: dict[str, Any]) -> None:
    # tconfigd clientmanager.go handleGetJWKSRequest: aggregate keys from Tokenetes instances.
    if message.get("type") != "GET_JWKS_REQUEST":
        return
    keys: list[dict[str, Any]] = []
    try:
        keys.extend((await tokenetes_jwks()).get("keys", []))
    except (LookupError, RuntimeError, TimeoutError) as exc:
        log(f"could not fetch tokenetes JWKS: {exc}")
    keys.extend(extra_keys)
    await websocket.send(
        json.dumps(
            {
                "id": message.get("id"),
                "type": "GET_JWKS_RESPONSE",
                "status": 200,
                "payload": {"keys": keys},
            }
        )
    )


async def handler(websocket: ServerConnection) -> None:
    peer = peer_spiffe_id(websocket)
    rules_file = {TOKENETES_ID: "generation-rules.json", AGENT_ID: "verification-rules.json"}
    if peer not in rules_file:
        log(f"rejecting unknown peer {peer!r}")
        await websocket.close(code=1008)
        return
    payload = json.loads((RULES_DIR / rules_file[peer]).read_text())
    initial = {"id": str(uuid.uuid4()), "type": "INITIAL_RULES_RESPONSE", "status": 201}
    await websocket.send(json.dumps({**initial, "payload": payload}))
    connections[peer] = websocket
    log(f"{peer} connected")
    try:
        async for raw in websocket:
            message = json.loads(raw)
            future = pending.get(str(message.get("id")))
            if future is not None and not future.done():
                future.set_result(message)
            elif peer == AGENT_ID:
                await answer_agent(websocket, message)
    finally:
        if connections.get(peer) is websocket:
            del connections[peer]
        log(f"{peer} disconnected")


async def control(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    status, body = 404, {"error": "not found"}
    try:
        request_line = (await reader.readline()).decode().split()
        headers: dict[str, str] = {}
        while (line := (await reader.readline()).decode().strip()) != "":
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        content = await reader.readexactly(int(headers.get("content-length", "0")))
        method, path = request_line[0], request_line[1]
        if method == "GET" and path == "/healthz":
            ready = TOKENETES_ID in connections and AGENT_ID in connections
            status, body = (200, {"ready": True}) if ready else (503, {"ready": False})
        elif method == "GET" and path == "/tokenetes-jwks":
            status, body = 200, await tokenetes_jwks()
        elif method == "PUT" and path == "/extra-jwks":
            extra_keys[:] = json.loads(content).get("keys", [])
            status, body = 200, {"keys": len(extra_keys)}
    except (LookupError, RuntimeError, TimeoutError, ValueError, IndexError) as exc:
        status, body = 503, {"error": str(exc)}
    data = json.dumps(body).encode()
    writer.write(
        f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n".encode()
        + data
    )
    await writer.drain()
    writer.close()


async def main() -> None:
    control_server = await asyncio.start_server(control, "0.0.0.0", 8080)  # noqa: S104
    async with serve(handler, "0.0.0.0", 8443, ssl=tls_context()), control_server:  # noqa: S104
        log("listening on :8443 (wss) and :8080 (control)")
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
