"""Builds the request data that is compared against ``tctx`` (private).

The comparison is only meaningful if it is made against exactly what the handler receives. So
this module does not parse anything itself: it runs FastAPI's own parameter and body validation
functions over the route's own parameter fields and the body FastAPI already read and cached on
the same :class:`~starlette.requests.Request`. Same input, same fields, same validator: the bound
values are the handler's values (a lax model coerces ``"10000"`` to ``10000`` for both).

The resulting mapping is ``path params + query params + body fields``; a name may come from only
one of those sources (checked at startup).
"""

from __future__ import annotations

import email.message
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel
from pydantic_core import PydanticUndefined
from starlette.requests import Request

from fastapi import params
from fastapi.dependencies.utils import request_body_to_args, request_params_to_args
from pytrat.core.errors import ConfigurationError
from pytrat.fastapi.responses import MalformedRequestError

if TYPE_CHECKING:
    from fastapi._compat import ModelField
    from fastapi.dependencies.models import Dependant

__all__ = ["RequestDataReader"]


def _is_json(content_type: str | None) -> bool:
    # Mirrors FastAPI's request handler: application/json and application/*+json are JSON.
    if not content_type:
        return False
    message = email.message.Message()
    message["content-type"] = content_type
    subtype = message.get_content_subtype()
    return message.get_content_maintype() == "application" and (
        subtype == "json" or subtype.endswith("+json")
    )


def _plain(value: object) -> object:
    return value.model_dump(mode="python") if isinstance(value, BaseModel) else value


def _model_fields(field: ModelField) -> tuple[str, ...] | None:
    annotation = field.field_info.annotation
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return tuple(annotation.model_fields)
    return None


@dataclass(frozen=True, slots=True)
class RequestDataReader:
    """Reads the validated path, query and body values of one route.

    Attributes:
        path_fields: The endpoint's own path parameters.
        query_fields: The endpoint's own query parameters.
        body_fields: The endpoint's own body parameters.
        embed_body_fields: FastAPI's decision to embed body parameters under their names.
        names: Every top-level name the reader can produce.
    """

    path_fields: tuple[ModelField, ...]
    query_fields: tuple[ModelField, ...]
    body_fields: tuple[ModelField, ...]
    embed_body_fields: bool
    names: frozenset[str]

    @classmethod
    def for_route(
        cls, dependant: Dependant, *, embed_body_fields: bool, label: str
    ) -> RequestDataReader:
        """Build a reader from FastAPI's dependency tree for the route.

        Raises:
            ConfigurationError: If two sources (path, query, body) provide the same name, or the
                body is a form/file body (not bindable; security review finding #4).
        """
        path_fields = tuple(dependant.path_params)
        query_fields = tuple(dependant.query_params)
        body_fields = tuple(dependant.body_params)
        if any(isinstance(field.field_info, params.Form) for field in body_fields):
            # FastAPI consumes form bodies as a stream, so the exact values the handler receives
            # cannot be re-read; refuse at startup rather than fail every request.
            raise ConfigurationError(
                f"{label}: form and file bodies cannot be bound to tctx; use a JSON body"
            )
        sources: list[Sequence[str]] = [
            [field.name for field in path_fields],
            [field.name for field in query_fields],
            cls._body_names(body_fields, embed_body_fields=embed_body_fields),
        ]
        names: set[str] = set()
        for source in sources:
            if clash := names.intersection(source):
                raise ConfigurationError(
                    f"{label}: parameter names {sorted(clash)} are provided by more than one of "
                    "path, query and body; bound request data would be ambiguous"
                )
            names.update(source)
        return cls(path_fields, query_fields, body_fields, embed_body_fields, frozenset(names))

    @staticmethod
    def _body_names(body_fields: Sequence[ModelField], *, embed_body_fields: bool) -> list[str]:
        if not body_fields:
            return []
        if embed_body_fields or len(body_fields) > 1:
            return [field.name for field in body_fields]
        # A single, non-embedded body: its fields are the top-level names. A non-model body
        # (a bare dict or list) has no declared names and cannot be bound.
        return list(_model_fields(body_fields[0]) or ())

    async def read(self, request: Request) -> dict[str, object]:
        """Return the validated values the handler receives.

        Raises:
            MalformedRequestError: ``REQUEST_MALFORMED`` if the request is invalid; FastAPI would
                reject it with 422 too.
        """
        errors: list[Any] = []
        path_values, path_errors = request_params_to_args(
            list(self.path_fields), request.path_params
        )
        query_values, query_errors = request_params_to_args(
            list(self.query_fields), request.query_params
        )
        errors.extend(path_errors + query_errors)
        data: dict[str, object] = {**path_values, **query_values}
        if self.body_fields:
            body_values, body_errors = await request_body_to_args(
                body_fields=list(self.body_fields),
                received_body=await self._received_body(request),
                embed_body_fields=self.embed_body_fields,
            )
            errors.extend(body_errors)
            data.update(self._flatten_body(body_values))
        if errors:
            # The validation errors echo submitted values, so only a fixed message is returned.
            raise MalformedRequestError("request parameters or body failed validation")
        return {name: _plain(value) for name, value in data.items()}

    def _flatten_body(self, body_values: Mapping[str, object]) -> Mapping[str, object]:
        if self.embed_body_fields or len(self.body_fields) != 1:
            return body_values
        value = body_values.get(self.body_fields[0].name)
        if isinstance(value, BaseModel):
            return value.model_dump(mode="python")
        return {}

    @staticmethod
    async def _received_body(request: Request) -> object:
        # FastAPI has already read the body before solving dependencies; Starlette caches both
        # the bytes and the parsed JSON on this Request, so this returns the very object FastAPI
        # validated for the handler.
        body = await request.body()
        if not body:
            return PydanticUndefined
        if not _is_json(request.headers.get("content-type")):
            return body
        return await request.json()
