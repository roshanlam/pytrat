"""Strict JSON decoding and deep freezing of JSON values (private)."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from types import MappingProxyType

type JsonObject = Mapping[str, object]
"""A JSON object. Values are str, int, float, bool, None, tuples or further JsonObjects."""


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


def strict_loads(data: bytes | str) -> object:
    """Decode JSON, rejecting duplicate keys and ``NaN``/``Infinity``.

    Raises:
        ValueError: If the input is not strict JSON (``DuplicateKeyError`` for duplicate keys).
    """
    return json.loads(data, object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant)


def compact_dumps(value: object) -> bytes:
    """Encode JSON deterministically: sorted keys, no whitespace, ASCII-safe."""
    return json.dumps(
        thaw(value), separators=(",", ":"), sort_keys=True, ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def freeze(value: object) -> object:
    """Recursively convert dicts to read-only mappings and lists to tuples.

    Raises:
        TypeError: If ``value`` contains a non-JSON type.
    """
    if value is None or isinstance(value, str | bool | int | float):
        return value
    if isinstance(value, Mapping):
        frozen: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("JSON object keys must be strings")
            frozen[key] = freeze(item)
        return MappingProxyType(frozen)
    if isinstance(value, Sequence) and not isinstance(value, bytes | bytearray):
        return tuple(freeze(item) for item in value)
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
