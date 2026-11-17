"""Strict Pydantic models for the YAML policy schema (version 1).

Every model forbids unknown keys, so a typo fails loudly instead of silently dropping a
constraint. Validation is strict: ``"true"`` is not a boolean and ``"3"`` is not an integer.
Cross-field rules live in :mod:`pytrat.policy.compiler` so that programmatic and YAML policies
share them.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Annotated

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    PlainValidator,
    StringConstraints,
)

__all__ = ["AgentsModel", "BindContext", "PolicyDocument", "ResourceModel"]

NonEmptyStr = Annotated[str, StringConstraints(min_length=1)]
ResourceName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")]


def _list_to_tuple(value: object) -> object:
    if isinstance(value, list):
        return tuple(value)
    if isinstance(value, tuple):
        return value
    raise ValueError("expected a list")


NameList = Annotated[tuple[NonEmptyStr, ...], BeforeValidator(_list_to_tuple)]

type BindContext = tuple[str, ...] | Mapping[str, str]
"""Either field paths bound identically on both sides, or ``{request.path: tctx.path}``."""

_BIND_CONTEXT_SHAPE = (
    "must be a list of field paths or a mapping of request path to tctx path, "
    "with non-empty string entries"
)


def _validate_bind_context(value: object) -> BindContext:
    if isinstance(value, list | tuple):
        if all(isinstance(item, str) and item for item in value):
            return tuple(value)
    elif isinstance(value, dict) and all(
        isinstance(key, str) and key and isinstance(item, str) and item
        for key, item in value.items()
    ):
        return MappingProxyType(dict(value))
    raise ValueError(_BIND_CONTEXT_SHAPE)


class _Model(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        hide_input_in_errors=True,
        arbitrary_types_allowed=True,
    )


class AgentsModel(_Model):
    """The ``agents`` block of a resource."""

    enabled: bool = False
    maximum_hops: Annotated[int, Field(ge=1)] | None = None
    minimum_assurance: NonEmptyStr | None = None
    require_chain_replacement: bool = False
    require_agent_context: bool = False
    require_verified_agent: bool = False
    allowed_originators: NameList | None = None


class ResourceModel(_Model):
    """One entry of ``resources``."""

    name: ResourceName
    path: NonEmptyStr
    method: NonEmptyStr
    require_transaction: bool = True
    require_workload_identity: bool = True
    allowed_scopes: NameList = ()
    allowed_callers: NameList | None = None
    bind_context: Annotated[BindContext, PlainValidator(_validate_bind_context)] = ()
    single_use: bool = False
    agents: AgentsModel | None = None


class PolicyDocument(_Model):
    """A policy document."""

    version: int
    trust_domain: NonEmptyStr
    assurance_levels: NameList | None = None
    resources: Annotated[
        tuple[ResourceModel, ...], BeforeValidator(_list_to_tuple), Field(min_length=1)
    ]
