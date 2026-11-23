"""Typer application: ``pytrat keys``, ``pytrat policy``, ``pytrat token``, ``pytrat tts``."""

from __future__ import annotations

import base64
import binascii
import json
import os
import sys
from datetime import timedelta
from pathlib import Path
from typing import Annotated

import typer

from pytrat.core import (
    SUPPORTED_DRAFTS,
    PyTraTError,
    StaticKeySet,
    TokenVerifier,
    VerificationKey,
    VerifierSettings,
    strict_loads,
)
from pytrat.core.constants import SUPPORTED_ALGORITHMS
from pytrat.core.crypto import generate_private_key, load_private_key_pem, private_key_to_pem
from pytrat.policy import load_policy

app = typer.Typer(no_args_is_help=True, add_completion=False, help=__doc__)
keys_app = typer.Typer(no_args_is_help=True, help="Generate signing keys and JWKS documents.")
policy_app = typer.Typer(no_args_is_help=True, help="Validate policy files.")
token_app = typer.Typer(no_args_is_help=True, help="Inspect Transaction Tokens.")
tts_app = typer.Typer(no_args_is_help=True, help="Run the reference Transaction Token Service.")
app.add_typer(keys_app, name="keys")
app.add_typer(policy_app, name="policy")
app.add_typer(token_app, name="token")
app.add_typer(tts_app, name="tts")

_PRIVATE_FILE_MODE = 0o600


def main() -> None:
    """Console-script entry point."""
    app()


def _fail(message: str, code: int = 1) -> typer.Exit:
    typer.secho(message, fg=typer.colors.RED, err=True)
    return typer.Exit(code)


@app.command()
def version() -> None:
    """Show the specification revisions this release implements."""
    for name, draft in SUPPORTED_DRAFTS.items():
        typer.echo(f"{name}: {draft}")


@app.command()
def demo(
    audit: Annotated[bool, typer.Option(help="Show the ledger's audit event.")] = True,
) -> None:
    """Watch a compromised service try to turn a $100 transfer into $9,000, and fail.

    Runs a gateway, two services and the reference TTS in-process with freshly generated keys.
    Nothing listens on a port and nothing is written outside a temporary directory.
    """
    import asyncio  # noqa: PLC0415 - keep the other commands' start-up light

    from pytrat.cli._demo.narrative import run_demo  # noqa: PLC0415

    if not asyncio.run(run_demo(show_audit=audit)):
        raise _fail("the demo did not behave as expected; please report this as a bug")


@app.command()
def init(
    directory: Annotated[Path, typer.Argument(help="Where to create the project.")] = Path(
        "pytrat-starter"
    ),
    trust_domain: Annotated[
        str, typer.Option(help="Trust Domain the TTS issues tokens for.")
    ] = "example.internal",
    force: Annotated[bool, typer.Option(help="Overwrite files from an earlier init.")] = False,
) -> None:
    """Create a runnable starter project: dev keys, a TTS config, a protected service and tests.

    The keys are for development only. Private keys are written with mode 0600 and git-ignored.
    """
    from pytrat.cli._starter import existing_files, write_starter  # noqa: PLC0415

    if not trust_domain or any(c.isspace() or c in "\"'\\" for c in trust_domain):
        raise _fail("trust domain must be a non-empty identifier without spaces or quotes")
    existing = existing_files(directory)
    if existing and not force:
        names = ", ".join(str(path) for path in existing)
        raise _fail(f"{names} already exist(s); pass --force to overwrite")
    write_starter(directory, trust_domain=trust_domain)
    typer.secho(f"Created a PyTraT starter project in {directory}/", fg="green")
    typer.echo(
        f"\n  cd {directory}\n"
        "  pytest                                            # the tests need no TTS\n\n"
        "Then run it for real, each in its own terminal:\n\n"
        "  pytrat tts serve --config tts.yaml --port 8080\n"
        "  uvicorn service:app --factory --port 8000\n"
        "  python gateway.py\n\n"
        "README.md explains every file."
    )


@keys_app.command("generate")
def keys_generate(
    kid: Annotated[str, typer.Option(help="Key identifier to publish in the JWKS.")],
    out: Annotated[Path, typer.Option(help="Directory for <kid>.pem and <kid>.jwks.json.")],
    alg: Annotated[str, typer.Option(help="Signing algorithm.")] = "ES256",
    force: Annotated[bool, typer.Option(help="Overwrite existing files.")] = False,
) -> None:
    """Generate a signing key: a 0600 PEM private key and a public JWKS (development use)."""
    if alg not in SUPPORTED_ALGORITHMS:
        raise _fail(f"unsupported algorithm {alg!r}; choose from {sorted(SUPPORTED_ALGORITHMS)}")
    if not kid or "/" in kid or kid.startswith("."):
        raise _fail("kid must be a simple file-name-safe identifier")
    out.mkdir(parents=True, exist_ok=True)
    pem_path, jwks_path = out / f"{kid}.pem", out / f"{kid}.jwks.json"
    if not force and (pem_path.exists() or jwks_path.exists()):
        raise _fail(f"{pem_path} or {jwks_path} already exists; pass --force to overwrite")
    private_key = generate_private_key(alg)
    _write_private(pem_path, private_key_to_pem(private_key))
    key = VerificationKey.from_public_key(kid, private_key.public_key(), alg)
    jwks_path.write_text(StaticKeySet([key]).to_json() + "\n", encoding="utf-8")
    typer.echo(f"private key: {pem_path} (mode 0600)")
    typer.echo(f"public JWKS: {jwks_path}")


@keys_app.command("jwks")
def keys_jwks(
    keys: Annotated[
        list[str],
        typer.Argument(help="Entries of the form KID=ALG=PATH.pem (private or public PEM)."),
    ],
) -> None:
    """Print a public JWKS combining several keys, e.g. the active and the retiring key."""
    from cryptography.hazmat.primitives.serialization import load_pem_public_key  # noqa: PLC0415

    verification_keys: list[VerificationKey] = []
    for entry in keys:
        try:
            kid, alg, path = entry.split("=", 2)
        except ValueError:
            raise _fail(f"expected KID=ALG=PATH, got {entry!r}") from None
        data = Path(path).read_bytes()
        try:
            public_key = (
                load_private_key_pem(data).public_key()
                if b"PRIVATE KEY" in data
                else load_pem_public_key(data)
            )
            verification_keys.append(
                VerificationKey.from_public_key(kid, public_key, alg)  # type: ignore[arg-type]
            )
        except (PyTraTError, ValueError) as error:
            raise _fail(f"{path}: {error}") from None
    typer.echo(StaticKeySet(verification_keys).to_json())


def _write_private(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    descriptor = os.open(path, flags, _PRIVATE_FILE_MODE)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
    path.chmod(_PRIVATE_FILE_MODE)


@policy_app.command("check")
def policy_check(
    path: Annotated[Path, typer.Argument(exists=True, dir_okay=False, help="Policy YAML.")],
    trust_domain: Annotated[
        str | None, typer.Option(help="Fail unless the policy targets this Trust Domain.")
    ] = None,
) -> None:
    """Compile a policy file exactly as a service would at startup."""
    try:
        policy_set = load_policy(path, expected_trust_domain=trust_domain)
    except PyTraTError as error:
        raise _fail(f"invalid policy: {error.detail}") from None
    typer.secho(f"OK: {len(policy_set.routes)} route(s)", fg=typer.colors.GREEN)
    for route, policy in policy_set.routes:
        typer.echo(f"  {route.method} {route.path} -> {policy.policy_id}")


@token_app.command("inspect")
def token_inspect(
    jwks: Annotated[
        Path | None, typer.Option(help="Trusted JWKS; when given, the token is verified.")
    ] = None,
    trust_domain: Annotated[str | None, typer.Option(help="Trust Domain for verification.")] = None,
    alg: Annotated[list[str] | None, typer.Option(help="Allowed algorithm (repeatable).")] = None,
    max_lifetime: Annotated[int, typer.Option(help="Maximum lifetime in seconds.")] = 300,
) -> None:
    """Decode a token read from standard input (never from argv, which leaks into history).

    Without --jwks the output is labelled UNVERIFIED. The signature is never printed.
    """
    raw = sys.stdin.read().strip()
    if not raw:
        raise _fail("no token on standard input")
    header, payload = _decode_unverified(raw)
    status = "UNVERIFIED (decoded only; do not trust these claims)"
    if jwks is not None:
        if trust_domain is None:
            raise _fail("--trust-domain is required with --jwks")
        settings = VerifierSettings(
            trust_domain=trust_domain,
            algorithms=frozenset(alg or ["ES256", "EdDSA", "PS256"]),
            max_lifetime=timedelta(seconds=max_lifetime),
        )
        try:
            verified = TokenVerifier(settings, StaticKeySet.from_jwks_file(jwks)).verify(raw)
        except PyTraTError as error:
            raise _fail(f"REJECTED: {error.reason.value}: {error.detail}") from None
        status = f"VERIFIED (kid={verified.kid}, alg={verified.alg})"
        payload = verified.claims.to_payload()
    typer.echo(status)
    typer.echo(json.dumps({"header": header, "payload": payload}, indent=2, sort_keys=True))


def _decode_unverified(raw: str) -> tuple[object, object]:
    segments = raw.split(".")
    if len(segments) != 3:
        raise _fail("not a compact JWS")
    try:
        header, payload = (
            strict_loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
            for part in segments[:2]
        )
    except (ValueError, binascii.Error):
        raise _fail("token header or payload is not valid base64url JSON") from None
    return header, payload


@tts_app.command("serve")
def tts_serve(
    config: Annotated[Path, typer.Option(exists=True, dir_okay=False, help="TTS YAML config.")],
    host: Annotated[str, typer.Option()] = "127.0.0.1",
    port: Annotated[int, typer.Option()] = 8080,
) -> None:
    """Run the reference Transaction Token Service."""
    import uvicorn  # noqa: PLC0415 - optional heavy import

    from pytrat.server import create_app_from_settings  # noqa: PLC0415

    uvicorn.run(create_app_from_settings(config), host=host, port=port)
