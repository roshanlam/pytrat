"""Fail-closed coverage of protected prefixes: startup refusal and the runtime guard."""

from typing import Annotated

import pytest
from fastapi import Depends, FastAPI, WebSocket
from starlette.responses import PlainTextResponse
from starlette.routing import Mount

from _fastapi_testkit import Kit, ledger_app, serve
from pytrat.core import ConfigurationError, ReasonCode
from pytrat.fastapi import PyTraTSettings, Transaction, TransactionMiddleware


def forgetful_app(kit: Kit):
    pytrat = kit.pytrat()
    app, _ = ledger_app(pytrat)
    ran: list[str] = []

    @app.post("/internal/forgotten")
    async def forgotten() -> dict[str, str]:
        ran.append("forgotten")
        return {"secret": "ledger-dump"}

    @app.get("/public/health")
    async def health() -> dict[str, str]:
        return {"ok": "yes"}

    return pytrat, app, ran


async def test_forgotten_dependency_is_refused_at_startup(kit: Kit) -> None:
    pytrat, app, _ = forgetful_app(kit)
    assert pytrat.unprotected_routes(app) == ("POST /internal/forgotten",)
    with pytest.raises(ConfigurationError, match="POST /internal/forgotten") as excinfo:
        async with pytrat.lifespan(app):
            pass
    assert "/internal/transfer" not in excinfo.value.detail
    with pytest.raises(ConfigurationError):
        pytrat.assert_all_routes_covered(app)


async def test_forgotten_dependency_is_403_at_runtime(kit: Kit) -> None:
    import httpx

    _pytrat, app, ran = forgetful_app(kit)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://ledger"
    ) as client:
        response = await client.post("/internal/forgotten", headers=kit.headers())
        health = await client.get("/public/health")
        missing = await client.get("/internal/nothing-here")
    assert response.status_code == 403
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json()["reason_code"] == "POLICY_NOT_FOUND"
    assert "ledger-dump" not in response.text
    assert ran == ["forgotten"]  # the guard is a backstop; startup refusal is the real defence
    assert health.status_code == 200
    assert missing.status_code == 403


async def test_exempt_route_works_without_a_transaction(kit: Kit) -> None:
    pytrat = kit.pytrat()
    app, _ = ledger_app(pytrat)

    @app.get("/internal/ping")
    @pytrat.exempt
    async def ping() -> dict[str, str]:
        return {"pong": "yes"}

    assert pytrat.unprotected_routes(app) == ()
    async with serve(app, pytrat) as client:
        response = await client.get("/internal/ping")
    assert response.json() == {"pong": "yes"}
    assert not pytrat.is_exempt(None)


async def test_denied_request_with_dependency_keeps_its_own_error(kit: Kit) -> None:
    pytrat = kit.pytrat()
    app, _ = ledger_app(pytrat)
    async with serve(app, pytrat) as client:
        response = await client.post("/internal/transfer", json={}, headers=kit.headers(""))
    assert response.json()["reason_code"] == "TOKEN_MISSING"


async def test_template_route_that_can_reach_a_protected_prefix_is_refused(kit: Kit) -> None:
    pytrat = kit.pytrat()
    app = FastAPI()

    @app.get("/{section}/report")
    async def report(section: str) -> None: ...

    @app.get("/files/{rest:path}")
    async def files(rest: str) -> None: ...

    @app.get("/other")
    async def other() -> None: ...

    async def root(request) -> PlainTextResponse:
        return PlainTextResponse("x")

    app.router.routes.append(Mount("/internal", routes=[]))
    pytrat_all = kit.pytrat(protected_prefixes=("/files/a", "/internal/deep"))
    assert set(pytrat_all.unprotected_routes(app)) == {
        "MOUNT /internal/{path}",
        "GET /files/{rest}",
    }
    assert pytrat.unprotected_routes(app) == ("GET /{section}/report", "MOUNT /internal/{path}")


async def websocket_messages(app: FastAPI, path: str) -> list[dict]:
    """Drive one websocket connection over raw ASGI and return what the app sent."""
    sent: list[dict] = []
    inbox = [{"type": "websocket.connect"}]

    async def receive() -> dict:
        return inbox.pop(0) if inbox else {"type": "websocket.disconnect", "code": 1000}

    async def send(message: dict) -> None:
        sent.append(message)

    scope = {
        "type": "websocket",
        "asgi": {"version": "3.0"},
        "path": path,
        "raw_path": path.encode(),
        "root_path": "",
        "scheme": "ws",
        "query_string": b"",
        "headers": [],
        "subprotocols": [],
    }
    await app(scope, receive, send)
    return sent


async def test_websocket_under_protected_prefix_is_refused(kit: Kit) -> None:
    pytrat = kit.pytrat()
    app = FastAPI()
    pytrat.install(app)

    @app.websocket("/internal/stream")
    async def stream(websocket: WebSocket) -> None:
        await websocket.accept()
        await websocket.send_text("secret")

    @app.websocket("/internal/open")
    @pytrat.exempt
    async def open_stream(websocket: WebSocket) -> None:
        await websocket.accept()
        await websocket.send_text("hello")

    assert pytrat.unprotected_routes(app) == ("WEBSOCKET /internal/stream",)
    refused = await websocket_messages(app, "/internal/stream")
    assert refused == [{"type": "websocket.close", "code": 1008}]
    allowed = await websocket_messages(app, "/internal/open")
    assert allowed[0]["type"] == "websocket.accept"
    assert allowed[1]["text"] == "hello"


def test_require_transaction_on_a_websocket_is_refused(kit: Kit) -> None:
    pytrat = kit.pytrat()
    app = FastAPI()
    dependency = pytrat.require_transaction(scope="payments.transfer")

    @app.websocket("/ws")
    async def stream(
        websocket: WebSocket, txn: Annotated[Transaction, Depends(dependency)]
    ) -> None: ...

    with pytest.raises(ConfigurationError, match="HTTP API routes only"):
        pytrat.prepare(app)


async def test_middleware_ignores_lifespan_and_unprotected_paths() -> None:
    calls: list[str] = []

    async def inner(scope, receive, send) -> None:
        calls.append(scope["type"])

    middleware = TransactionMiddleware(
        inner, settings=PyTraTSettings(service="s", protected_prefixes=("/x",)), is_exempt=bool
    )
    await middleware({"type": "lifespan"}, None, None)
    await middleware({"type": "http", "path": "/y"}, None, None)
    assert calls == ["lifespan", "http"]


async def test_root_path_is_stripped_before_matching_prefixes() -> None:
    sent: list[dict] = []

    async def inner(scope, receive, send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"leak"})

    async def send(message) -> None:
        sent.append(message)

    middleware = TransactionMiddleware(
        inner, settings=PyTraTSettings(service="s", protected_prefixes=("/x/",)), is_exempt=bool
    )
    await middleware({"type": "http", "path": "/api/x/1", "root_path": "/api"}, None, send)
    assert sent[0]["status"] == 403
    assert b"leak" not in b"".join(m.get("body", b"") for m in sent)


@pytest.mark.parametrize(
    ("prefixes", "error"),
    [("/internal", "not a string"), (["internal"], "start with")],
)
def test_invalid_prefixes_are_rejected(prefixes, error) -> None:
    with pytest.raises(ConfigurationError, match=error):
        PyTraTSettings(service="s", protected_prefixes=prefixes)


def test_settings_validation() -> None:
    with pytest.raises(ConfigurationError):
        PyTraTSettings(service="")
    settings = PyTraTSettings(service="s", protected_prefixes=["/", "/a/", "/a"])
    assert settings.protected_prefixes == ("/", "/a")
    assert settings.is_protected("/anything")
    assert ReasonCode.POLICY_NOT_FOUND
