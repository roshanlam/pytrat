"""Strict JSON decoding and deep freezing of JSON values (private)."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import Final

type JsonObject = Mapping[str, object]
"""A JSON object. Values are str, int, float, bool, None, tuples or further JsonObjects."""

# PyTraT profile: frozen JSON values (claim objects such as tctx, rctx, act) nest at most this
# deep. The bound is far above any legitimate claim and well below the interpreter's recursion
# limit, so excessive nesting is a deterministic validation failure, never a RecursionError.
MAX_FREEZE_DEPTH: Final = 64


class DuplicateKeyError(ValueError):
    """A JSON object contained the same key twice."""


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            # Different parsers resolve duplicates differently; ambiguity is an attack surface.
            raise DuplicateKeyError("duplicate key in JSON object")
        result[key] = value
    return result


def _reject_constant(name: str) -> object:
    raise ValueError(f"non-standard JSON constant {name}")


def _finite_float(literal: str) -> float:
    value = float(literal)
    # A literal such as 1e400 overflows to infinity, which is just Infinity spelled differently.
    if not math.isfinite(value):
        raise ValueError("number is not finite")
    return value


def _reject_lone_surrogates(value: object) -> None:
    # I-JSON (RFC 7493 §2.1): strings must be valid Unicode. A lone surrogate decodes in Python
    # but cannot be encoded as UTF-8, so it would fail later when hashed, signed or compared.
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeEncodeError:
                raise ValueError("string contains a lone surrogate") from None
        elif isinstance(item, dict):
            pending.extend(item)
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)


def strict_loads(data: bytes | str) -> object:
    """Decode JSON, rejecting duplicate keys, non-finite numbers and lone surrogates.

    ``NaN``, ``Infinity`` and literals that overflow to infinity (``1e400``) are rejected, as
    are strings that are not valid Unicode (I-JSON, RFC 7493 §2.1).

    Raises:
        ValueError: If the input is not strict JSON (``DuplicateKeyError`` for duplicate keys),
            including nesting too deep for the decoder.
    """
    try:
        value = json.loads(
            data,
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except RecursionError:
        raise ValueError("JSON nesting is too deep") from None
    _reject_lone_surrogates(value)
    return value


def compact_dumps(value: object) -> bytes:
    """Encode JSON deterministically: sorted keys, no whitespace, ASCII-safe."""
    return json.dumps(
        thaw(value), separators=(",", ":"), sort_keys=True, ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def freeze(value: object) -> object:
    """Recursively convert dicts to read-only mappings and lists to tuples.

    Raises:
        TypeError: If ``value`` contains a non-JSON type or nests deeper than
            :data:`MAX_FREEZE_DEPTH`.
    """
    return _freeze(value, 0)


def _freeze(value: object, depth: int) -> object:
    if value is None or isinstance(value, str | bool | int | float):
        return value
    if depth >= MAX_FREEZE_DEPTH:
        raise TypeError("JSON nesting is too deep")
    if isinstance(value, Mapping):
        frozen: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("JSON object keys must be strings")
            frozen[key] = _freeze(item, depth + 1)
        return MappingProxyType(frozen)
    if isinstance(value, Sequence) and not isinstance(value, bytes | bytearray):
        return tuple(_freeze(item, depth + 1) for item in value)
    raise TypeError(f"unsupported JSON type {type(value).__name__}")


def freeze_object(value: object) -> JsonObject:
    """Freeze a JSON object (not any other JSON value).

    Raises:
        TypeError: If ``value`` is not a JSON object.
    """
    if not isinstance(value, Mapping):
        raise TypeError("expected a JSON object")
    frozen = freeze(value)
    assert isinstance(frozen, Mapping)  # noqa: S101 - narrowing only; freeze preserves mappings
    return frozen


def thaw(value: object) -> object:
    """Inverse of :func:`freeze`: produce plain dicts and lists suitable for ``json.dumps``."""
    if isinstance(value, Mapping):
        return {key: thaw(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [thaw(item) for item in value]
    return value
