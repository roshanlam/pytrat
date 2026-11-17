"""Fuzz ``strict_loads``, the JSON decoder behind every token, JWKS and form field.

Invariants: only ``ValueError`` (including ``DuplicateKeyError`` and ``UnicodeDecodeError``) is
raised, and whatever it accepts the standard library decodes to the same value with no duplicate
keys and no non-finite number (``NaN``, ``Infinity`` or an overflowing literal such as ``1e400``).
"""

from __future__ import annotations

import json
import math
from collections.abc import Iterator

from fuzz._harness import fuzz
from pytrat.core import strict_loads


def _has_duplicates_or_constants(raw: bytes) -> bool:
    found = False

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        nonlocal found
        found = found or len({name for name, _ in items}) != len(items)
        return dict(items)

    def constant(_: str) -> float:
        nonlocal found
        found = True
        return math.nan

    json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    return found


def _all_finite(value: object) -> bool:
    # Iterative: accepted documents may nest deeper than the interpreter's recursion limit.
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, float) and not math.isfinite(item):
            return False
        if isinstance(item, dict):
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return True


def TestOneInput(data: bytes) -> None:  # noqa: N802 - name required by Atheris
    """Decode ``data`` strictly and compare with the standard decoder."""
    try:
        value = strict_loads(data)
    except ValueError:
        return
    if not _all_finite(value):
        raise AssertionError("strict_loads accepted a non-finite number")
    try:
        lenient_value = json.loads(data)
        duplicates_or_constants = _has_duplicates_or_constants(data)
        agrees = lenient_value == value
    except RecursionError:
        return  # a limit of the oracle, not of the code under test
    if duplicates_or_constants:
        raise AssertionError("strict_loads accepted duplicate keys or a non-standard constant")
    if not agrees:
        raise AssertionError("strict_loads disagrees with json.loads")


def seeds() -> Iterator[bytes]:
    """Valid, duplicate-key, constant and deeply nested documents."""
    yield b'{"a": 1, "b": [true, false, null], "c": {"d": "e"}}'
    yield b'{"a": 1, "a": 2}'
    yield b'{"a": {"b": 1, "b": 1}}'
    yield b"[NaN, Infinity, -Infinity]"
    yield b'"\\ud800"'
    yield b"\xef\xbb\xbf{}"
    yield b"1e400"  # regression: decoded to infinity
    yield b'{"amount": -1e999}'
    yield b"[" * 64 + b"]" * 64


if __name__ == "__main__":
    fuzz(TestOneInput)
