"""Flatten the strict configuration models for comparison with the reference pages.

A reference table row looks like ``| `dotted.key` | type | default | description |``. Items of a
list of objects are written ``key[].member``; values of a mapping keyed by an id are written
``key.<id>.member``.
"""

from __future__ import annotations

import re
import types
import typing
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from pydantic import BaseModel
from pydantic_core import PydanticUndefined

ROW = re.compile(r"^\|\s*`(?P<key>[^`]+)`\s*\|(?P<type>[^|]*)\|(?P<default>[^|]*)\|")


@dataclass(frozen=True)
class Field:
    """One configuration key."""

    key: str
    default: str
    leaf: bool


def _model_in(annotation: object) -> tuple[type[BaseModel], str] | None:
    """Return the nested model and the key suffix used to reach it, if any."""
    origin = typing.get_origin(annotation)
    args = typing.get_args(annotation)
    if origin is typing.Annotated:
        return _model_in(args[0])
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return annotation, "."
    if origin in (types.UnionType, typing.Union):
        for arg in args:
            found = _model_in(arg)
            if found is not None:
                return found
        return None
    containers = {tuple: (0, "[]."), dict: (1, ".<id>.")}
    if origin in containers and args:
        position, suffix = containers[origin]
        item = _model_in(args[position]) if len(args) > position else None
        return None if item is None else (item[0], suffix)
    return None


def render_default(value: object) -> str:  # noqa: PLR0911 - one arm per value kind
    """The default as written in the reference tables (YAML spelling)."""
    if value is PydanticUndefined:
        return "required"
    if value is None:
        return "unset"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, Enum):
        return str(value.value)
    if isinstance(value, tuple | list):
        return "[" + ", ".join(render_default(item) for item in value) + "]"
    if isinstance(value, Mapping):
        return "{}" if not value else str(dict(value))
    return str(value)


def fields(model: type[BaseModel], prefix: str = "") -> Iterator[Field]:
    """Every key of ``model``, depth first, in declaration order."""
    for name, info in model.model_fields.items():
        key = prefix + name
        nested = _model_in(info.annotation)
        if nested is None:
            yield Field(key, render_default(info.default), leaf=True)
            continue
        nested_model, suffix = nested
        default = "required" if info.default is PydanticUndefined else "see below"
        yield Field(key, default, leaf=False)
        yield from fields(nested_model, key + suffix)


def documented_rows(page: Path) -> dict[str, str]:
    """``key -> default cell`` for every reference-table row on ``page``."""
    rows: dict[str, str] = {}
    for line in page.read_text(encoding="utf-8").splitlines():
        match = ROW.match(line)
        if match:
            rows[match["key"]] = match["default"].strip().strip("`")
    return rows
