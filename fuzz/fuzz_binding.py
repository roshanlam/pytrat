"""Fuzz ``ContextBinding.check`` with arbitrary ``tctx`` and request data.

Input layout: ``binding byte || tctx JSON || NUL || request JSON``. A JSON value that is not an
object is bound as ``amount_minor``.

Invariants: only :class:`PyTraTError` is raised, and when a plain (non-derived) binding passes,
an independent oracle agrees that every bound request value equals the authorized value with
exact types at every level, and that no two distinct object keys collapse into one when
compared (which would let a request smuggle a value the service reads but the check never saw).
"""

from __future__ import annotations

import json
import unicodedata
from collections.abc import Iterator, Mapping

from fuzz._harness import choose, fuzz, join, split
from pytrat.core import ContextBinding, Derived, PyTraTError

_PLAIN = (
    ContextBinding.compile(["amount_minor", "beneficiary", "nested.value"]),
    ContextBinding.compile({"amount": "amount_minor", "to": "beneficiary.account"}),
)


def _major_to_minor(value: object) -> object:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("amount must be an integer")
    return value * 100


_DERIVED = ContextBinding.compile(
    [Derived("amount_major", "amount_minor", _major_to_minor, "major_to_minor")]
)
_BINDINGS = (*_PLAIN, _DERIVED)
_MAX_ORACLE_DEPTH = 200


class _UnbindableError(Exception):
    """The oracle considers the value unbindable or ambiguous."""


def _oracle(value: object, depth: int = 0) -> object:
    if depth > _MAX_ORACLE_DEPTH or isinstance(value, float):
        raise _UnbindableError
    if isinstance(value, str):
        return ("str", unicodedata.normalize("NFC", value))
    if isinstance(value, dict):
        normalised = {unicodedata.normalize("NFC", name): item for name, item in value.items()}
        if len(normalised) != len(value):
            raise _UnbindableError  # two keys compare equal: ambiguous
        return ("dict", {name: _oracle(item, depth + 1) for name, item in normalised.items()})
    if isinstance(value, list):
        return ("list", [_oracle(item, depth + 1) for item in value])
    return (type(value).__name__, value)


def _resolve(data: Mapping[str, object], path: tuple[str, ...]) -> object:
    current: object = data
    for part in path:
        if not isinstance(current, Mapping) or part not in current:
            raise AssertionError("binding passed although a bound value is absent")
        current = current[part]
    return current


def _as_object(raw: bytes) -> dict[str, object] | None:
    try:
        value = json.loads(raw)
    except (ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else {"amount_minor": value}


def TestOneInput(data: bytes) -> None:  # noqa: N802 - name required by Atheris
    """Check one request against one authorized context."""
    binding, rest = choose(data, _BINDINGS)
    raw_tctx, raw_request = split(rest, 2)
    tctx, request_data = _as_object(raw_tctx), _as_object(raw_request)
    if tctx is None or request_data is None:
        return
    try:
        binding.check(tctx, request_data)
    except PyTraTError:
        return
    if binding is _DERIVED:
        return
    for rule in binding.rules:
        try:
            authorized = _oracle(_resolve(tctx, rule.tctx_path))
            requested = _oracle(_resolve(request_data, rule.request_path))
        except _UnbindableError:
            raise AssertionError("binding passed on an unbindable or ambiguous value") from None
        if authorized != requested:
            raise AssertionError("binding passed although the values differ")


def seeds() -> Iterator[bytes]:
    """Matching and mismatching contexts, including type-juggling attempts."""
    tctx = {"amount_minor": 10000, "beneficiary": {"account": "B"}, "nested": {"value": [1, "x"]}}
    encoded = json.dumps(tctx).encode()
    yield bytes([0]) + join(encoded, encoded)
    yield bytes([0]) + join(encoded, json.dumps({**tctx, "amount_minor": 10000.0}).encode())
    yield bytes([0]) + join(encoded, json.dumps({**tctx, "amount_minor": "10000"}).encode())
    yield bytes([0]) + join(b"true", b"1")
    yield bytes([0]) + join(
        json.dumps({**tctx, "beneficiary": {"café": "B"}}).encode(),
        json.dumps({**tctx, "beneficiary": {"café": "X", "café": "B"}}).encode(),
    )
    # Regression: a deeply nested bound value raised RecursionError.
    deep = b'{"amount_minor": ' + b"[" * 1500 + b"]" * 1500 + b"}"
    yield bytes([0]) + join(deep, deep)
    yield bytes([1]) + join(encoded, b'{"amount": 10000, "to": "B"}')
    yield bytes([2]) + join(encoded, b'{"amount_major": 100}')
    yield bytes([2]) + join(encoded, b'{"amount_major": "x"}')


if __name__ == "__main__":
    fuzz(TestOneInput)
