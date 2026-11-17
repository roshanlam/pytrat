"""Container entrypoint for the Docker Compose deployment. All configuration comes from env vars.

    python -m payment_demo.container init           # one-shot: generate CA, certs and keys
    python -m payment_demo.container healthcheck URL
    python -m payment_demo.container client [--amount-minor N]
    uvicorn payment_demo.container:gateway_app --factory --ssl-keyfile ... --ssl-certfile ...

Environment:

    PYTRAT_DEMO_{TTS,GATEWAY,PAYMENT,LEDGER}_URL  https:// origin of each service (required)
    PYTRAT_DEMO_PUBLIC_DIR    CA certificate and JWKS files        (default /pki/public)
    PYTRAT_DEMO_PRIVATE_DIR   this container's own private keys    (default /pki/private)
    PYTRAT_DEMO_PRIVATE_ROOT  init only: one subdirectory per service (default /pki/out)
    PYTRAT_DEMO_WORK_DIR      writable scratch (TTS audit database) (default /tmp/pytrat)
    PYTRAT_DEMO_COMPROMISED   payment only: "1" rewrites the amount  (default "0")

Every value is checked and anything unexpected stops the process: a misconfigured container must
fail to start rather than run with weaker settings.
"""

from __future__ import annotations

import argparse
import http.client
import json
import logging
import os
import ssl
import sys
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from payment_demo.lab import Lab, Urls

if TYPE_CHECKING:
    from fastapi import FastAPI

_SERVICES = ("tts", "gateway", "payment", "ledger")


def _env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if not value:
        raise SystemExit(f"{name} must be set")
    return value


def _https_url(name: str) -> str:
    raw = _env(name)
    parts = urlsplit(raw)
    # The container network is not loopback: PyTraT would refuse http:// anyway; fail early.
    if parts.scheme != "https" or not parts.hostname or parts.path not in ("", "/"):
        raise SystemExit(f"{name} must be an https:// origin")
    return raw.rstrip("/")


def urls_from_env() -> Urls:
    """Service origins from ``PYTRAT_DEMO_*_URL``; each must be ``https://``."""
    return Urls(**{name: _https_url(f"PYTRAT_DEMO_{name.upper()}_URL") for name in _SERVICES})


def public_dir() -> Path:
    """Directory holding the demo CA certificate and public JWKS files."""
    return Path(_env("PYTRAT_DEMO_PUBLIC_DIR", "/pki/public"))


def lab_from_env() -> Lab:
    """The lab view of this container: its own private keys, everyone's public keys."""
    public = public_dir()
    return Lab.load(
        directory=Path(_env("PYTRAT_DEMO_WORK_DIR", "/tmp/pytrat")),  # noqa: S108 - tmpfs mount
        key_directory=Path(_env("PYTRAT_DEMO_PRIVATE_DIR", "/pki/private")),
        public_directory=public,
        urls=urls_from_env(),
        ca_bundle=public / "ca.crt",
    )


def _compromised() -> bool:
    raw = _env("PYTRAT_DEMO_COMPROMISED", "0")
    if raw not in ("0", "1"):
        raise SystemExit('PYTRAT_DEMO_COMPROMISED must be "0" or "1"')
    return raw == "1"


def _audit_to_stdout() -> None:
    """Send PyTraT audit events (one JSON object per line) to stdout for ``docker compose logs``.

    This module is an application entrypoint, so it may configure logging; the library never does.
    """
    audit = logging.getLogger("pytrat.audit")
    if not audit.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(message)s"))
        audit.addHandler(handler)
        audit.setLevel(logging.INFO)
        audit.propagate = False


def tts_app() -> FastAPI:
    """The reference TTS, configured from the environment."""
    from payment_demo.services import create_tts  # noqa: PLC0415 - keep healthchecks light
    from pytrat.core import LoggingSink  # noqa: PLC0415

    _audit_to_stdout()
    return create_tts(lab_from_env(), LoggingSink())


def gateway_app() -> FastAPI:
    """The API gateway, configured from the environment."""
    from payment_demo.services import create_gateway  # noqa: PLC0415

    _audit_to_stdout()
    return create_gateway(lab_from_env())


def payment_app() -> FastAPI:
    """The payment service; tampering when ``PYTRAT_DEMO_COMPROMISED=1``."""
    from payment_demo.services import create_payment  # noqa: PLC0415
    from pytrat.core import LoggingSink  # noqa: PLC0415

    _audit_to_stdout()
    compromised = _compromised()
    if compromised:
        print("payment-service is running COMPROMISED (tampers with amounts)", file=sys.stderr)
    return create_payment(lab_from_env(), compromised=compromised, audit=LoggingSink())


def ledger_app() -> FastAPI:
    """The ledger, configured from the environment."""
    from payment_demo.services import create_ledger  # noqa: PLC0415
    from pytrat.core import LoggingSink  # noqa: PLC0415

    _audit_to_stdout()
    return create_ledger(lab_from_env(), audit=LoggingSink())


def init() -> int:
    """Generate CA, TLS certificates and JWT keys into the shared volumes (once per volume)."""
    from payment_demo.pki import TlsService, provision  # noqa: PLC0415

    urls = urls_from_env()
    services = []
    for name in _SERVICES:
        host = urlsplit(getattr(urls, name)).hostname
        if host is None:  # pragma: no cover - rejected by urls_from_env
            raise SystemExit(f"no host in the {name} URL")
        # Only the gateway is published to the host, on 127.0.0.1.
        extra_dns, ips = (("localhost",), ("127.0.0.1",)) if name == "gateway" else ((), ())
        services.append(TlsService(name, (host, *extra_dns), ips))
    fresh = provision(public_dir(), Path(_env("PYTRAT_DEMO_PRIVATE_ROOT", "/pki/out")), services)
    print(
        "generated fresh demo CA, TLS certificates and keys" if fresh else "keeping existing keys"
    )
    return 0


def healthcheck(url: str) -> int:
    """Exit 0 if ``url`` answers over HTTPS with a certificate the demo CA vouches for."""
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.hostname is None:
        print("healthcheck URL must be https://", file=sys.stderr)
        return 2
    context = ssl.create_default_context(cafile=public_dir() / "ca.crt")
    connection = http.client.HTTPSConnection(
        parts.hostname, parts.port or 443, context=context, timeout=3
    )
    try:
        connection.request("GET", parts.path or "/")
        status = connection.getresponse().status
    except (OSError, http.client.HTTPException) as error:
        print(f"unhealthy: {type(error).__name__}", file=sys.stderr)
        return 1
    finally:
        connection.close()
    return 0 if status < 500 else 1


def client(amount_minor: int) -> int:
    """Act as the logged-in user: ask the gateway for a transfer; print status and body as JSON."""
    import httpx  # noqa: PLC0415

    from payment_demo.scenario import TRANSFER  # noqa: PLC0415

    lab = lab_from_env()
    token = lab.user_access_token()
    body = {**TRANSFER, "amount_minor": amount_minor}
    with httpx.Client(verify=lab.tls_verify(), follow_redirects=False, timeout=10.0) as user:
        response = user.post(
            f"{lab.urls.gateway}/transfers",
            json=body,
            headers={"Authorization": f"Bearer {token.reveal()}"},
        )
    print(json.dumps({"status": response.status_code, "body": response.json()}))
    return 0


def main(argv: list[str] | None = None) -> int:
    """Dispatch a container command."""
    parser = argparse.ArgumentParser(prog="python -m payment_demo.container")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init")
    check = commands.add_parser("healthcheck")
    check.add_argument("url")
    user = commands.add_parser("client")
    user.add_argument("--amount-minor", type=int, default=10_000)
    args = parser.parse_args(argv)
    if args.command == "init":
        return init()
    if args.command == "healthcheck":
        return healthcheck(args.url)
    return client(args.amount_minor)


if __name__ == "__main__":
    raise SystemExit(main())
