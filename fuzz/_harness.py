"""Shared plumbing for the harnesses: a fixed clock, runtime keys and input splitting.

Keys are generated when a harness module is imported; no key material is ever stored in the
repository or the corpus. Harnesses use fixed ``kid`` values so seed inputs can name them.
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from pytrat.core.crypto import sign_raw
from pytrat.core.testing import FrozenClock, TestKey, b64url, generate_test_key

__all__ = [
    "CORPUS_DIR",
    "FUZZ_DIR",
    "NOW",
    "TRUST_DOMAIN",
    "assert_no_token",
    "choose",
    "clock",
    "fuzz",
    "harness_names",
    "join",
    "key",
    "overlay",
    "sign_segments",
    "split",
    "text",
]

NOW = 1_795_000_000
TRUST_DOMAIN = "payments.internal"
_SEPARATOR = b"\x00"
# Same pattern as the repository conftest: three base64url segments, the first two JSON objects.
_COMPACT_JWS = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}")


FUZZ_DIR = Path(__file__).resolve().parent
CORPUS_DIR = FUZZ_DIR / "corpus"


def harness_names() -> list[str]:
    """Module names of every harness (``fuzz_<target>``), sorted."""
    return sorted(path.stem for path in FUZZ_DIR.glob("fuzz_*.py"))


def clock() -> FrozenClock:
    """A clock frozen at :data:`NOW`, so seed timestamps stay valid forever."""
    return FrozenClock(NOW)


def key(kid: str, alg: str = "ES256") -> TestKey:
    """A freshly generated key with a fixed ``kid``."""
    return generate_test_key(alg, kid=kid)


def split(data: bytes, parts: int) -> list[bytes]:
    """Split ``data`` into exactly ``parts`` pieces on NUL bytes (missing pieces are empty)."""
    pieces = data.split(_SEPARATOR, parts - 1)
    return pieces + [b""] * (parts - len(pieces))


def join(*pieces: bytes) -> bytes:
    """Inverse of :func:`split`, for building seeds."""
    return _SEPARATOR.join(pieces)


def choose[T](data: bytes, options: Sequence[T]) -> tuple[T, bytes]:
    """Use the first byte of ``data`` to pick one of ``options``; return it and the rest."""
    if not data:
        return options[0], b""
    return options[data[0] % len(options)], data[1:]


def text(data: bytes) -> str:
    """Decode as a web framework would hand a header or field value to PyTraT."""
    return data.decode("utf-8", errors="replace")


def overlay(base: Mapping[str, object], raw: bytes) -> bytes:
    """Serialise ``base`` with a JSON object of overrides applied (``null`` deletes a member).

    If ``raw`` is not a JSON object it is returned unchanged, so the fuzzer can still reach the
    malformed-JSON paths.
    """
    try:
        overrides = json.loads(raw)
    except (ValueError, RecursionError):
        return raw
    if not isinstance(overrides, dict):
        return raw
    merged = dict(base)
    for name, value in overrides.items():
        if value is None:
            merged.pop(name, None)
        else:
            merged[name] = value
    try:
        return json.dumps(merged).encode()
    except (ValueError, RecursionError):
        return raw


def sign_segments(header: bytes, payload: bytes, signer: TestKey) -> str:
    """A compact JWS over arbitrary header and payload bytes with a valid signature."""
    signing_input = f"{b64url(header)}.{b64url(payload)}"
    signature = sign_raw(signing_input.encode(), signer.private_key, signer.alg)
    return f"{signing_input}.{b64url(signature)}"


def assert_no_token(error: BaseException) -> None:
    """Fail if an error's message or repr contains a compact JWS (CLAUDE.md invariant 4)."""
    if _COMPACT_JWS.search(str(error)) or _COMPACT_JWS.search(repr(error)):
        raise AssertionError(f"{type(error).__name__} message contains a compact JWS")


def fuzz(test_one_input: Callable[[bytes], None]) -> None:
    """Run ``test_one_input`` under Atheris with libFuzzer arguments from ``sys.argv``."""
    import atheris  # noqa: PLC0415 - optional dependency, present only in the fuzz image

    # Every PyTraT module is already imported by the harness; instrument all loaded bytecode.
    atheris.instrument_all()
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
