"""Adapting Django requests and responses to the framework-agnostic pipeline (private)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar, Final

from pydantic import BaseModel, ValidationError

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.http.request import RawPostDataException
from pytrat.core import (
    InboundRequest,
    PyTraTError,
    RequestError,
    problem_details,
    strict_loads,
)
from pytrat.core.constants import TXN_TOKEN_HEADER
from pytrat.policy import CompiledPolicy

PROBLEM_CONTENT_TYPE: Final = "application/problem+json"
JSON_CONTENT_TYPE: Final = "application/json"

# CGI/WSGI META keys for headers that do not carry the ``HTTP_`` prefix.
_UNPREFIXED_HEADERS: Final = {"CONTENT_TYPE": "Content-Type", "CONTENT_LENGTH": "Content-Length"}
_TXN_TOKEN_META_KEY: Final = "HTTP_" + TXN_TOKEN_HEADER.upper().replace("-", "_")


class RequestDataError(RequestError):
    """The request body or parameters cannot be turned into unambiguous request data."""


class UnsupportedBodyError(RequestDataError):
    """A body must be bound but is not ``application/json``."""

    http_status: ClassVar[int] = 415


class BodyValidationError(RequestDataError):
    """The JSON body failed validation against the view's ``body_model``."""

    http_status: ClassVar[int] = 422


def inbound_request(request: HttpRequest) -> InboundRequest:
    """Convert a Django request into the transport facts the enforcer needs.

    Header names are reconstructed from ``request.META`` (``HTTP_TXN_TOKEN`` -> ``Txn-Token``)
    and ``peer`` is ``REMOTE_ADDR``.

    WSGI (PEP 3333) and Django's ASGI handler both join repeated headers into one value with a
    comma. A compact JWS never contains a comma, so a ``Txn-Token`` value containing one means the
    header was sent more than once. It is split back into separate values here so the enforcer's
    "exactly one ``Txn-Token``" check (txn-tokens-11 §12.1) rejects it as ``TOKEN_MALFORMED``.
    """
    meta = _meta(request)
    headers: list[tuple[str, str]] = []
    for key, value in meta.items():
        if not isinstance(value, str):
            continue
        if key == _TXN_TOKEN_META_KEY:
            # txn-tokens-11 §12.1: exactly one token; a comma means a joined duplicate.
            headers.extend((TXN_TOKEN_HEADER, part) for part in value.split(","))
        elif key in _UNPREFIXED_HEADERS:
            headers.append((_UNPREFIXED_HEADERS[key], value))
        elif key.startswith("HTTP_"):
            headers.append((_header_name(key[5:]), value))
    peer = meta.get("REMOTE_ADDR")
    return InboundRequest(tuple(headers), peer if isinstance(peer, str) and peer else None)


def request_data(
    request: HttpRequest,
    url_kwargs: Mapping[str, object],
    policy: CompiledPolicy,
    body_model: type[BaseModel] | None,
) -> tuple[dict[str, object], BaseModel | None]:
    """Build the data compared against ``tctx``: JSON body, URL kwargs and query parameters.

    Returns:
        The merged request data and the validated body model instance (if ``body_model`` is set).
        With a ``body_model`` the body part is ``model_dump(mode="python")`` of the validated
        instance, so the values compared are exactly the values the view receives.

    Raises:
        RequestDataError: Duplicate JSON keys, a non-object body, a repeated query parameter, or a
            name present in more than one source (400).
        UnsupportedBodyError: A body that must be bound is not ``application/json`` (415).
        BodyValidationError: The body does not validate against ``body_model`` (422).
    """
    body, validated = _body_data(request, policy, body_model)
    merged: dict[str, object] = dict(body)
    _merge(merged, url_kwargs, "URL parameter")
    _merge(merged, _query_data(request), "query parameter")
    return merged, validated


def problem_response(
    error: PyTraTError, *, transaction_id: str | None = None, debug: bool = False
) -> HttpResponse:
    """Render ``error`` as an RFC 9457 ``application/problem+json`` response.

    The document comes from :func:`pytrat.core.problem_details`, shared with every integration.
    ``transaction_id`` fills in the verified ``txn`` for errors raised by the view itself. 401
    responses carry ``WWW-Authenticate: Txn-Token``.
    """
    if error.transaction_id is None and transaction_id is not None:
        error.transaction_id = transaction_id
    body = problem_details(error, include_detail=debug)
    response: HttpResponse = JsonResponse(
        body, status=error.http_status, content_type=PROBLEM_CONTENT_TYPE
    )
    if error.http_status == 401:
        response["WWW-Authenticate"] = TXN_TOKEN_HEADER
    return response


def _header_name(meta_suffix: str) -> str:
    return "-".join(part.capitalize() for part in meta_suffix.split("_"))


def _meta(request: HttpRequest) -> Mapping[str, object]:
    meta: object = request.META
    if not isinstance(meta, Mapping):  # pragma: no cover - Django always provides a dict
        raise TypeError("request.META is not a mapping")
    return meta


def _raw_body(request: HttpRequest) -> bytes | None:
    """The raw body, or None if Django already consumed the stream (e.g. multipart parsing)."""
    try:
        body: object = request.body
    except RawPostDataException:
        return None
    return body if isinstance(body, bytes) else None


def _content_type(request: HttpRequest) -> str:
    content_type: object = request.content_type
    return content_type.lower() if isinstance(content_type, str) else ""


def _body_data(
    request: HttpRequest, policy: CompiledPolicy, body_model: type[BaseModel] | None
) -> tuple[Mapping[str, object], BaseModel | None]:
    raw_body = _raw_body(request)
    is_json = _content_type(request) == JSON_CONTENT_TYPE
    if body_model is None and raw_body == b"":
        return {}, None
    if not is_json:
        if body_model is not None or policy.binding.rules:
            raise UnsupportedBodyError("a bound request body must be application/json")
        # Nothing is bound, so a non-JSON body (e.g. a form) is the view's business.
        return {}, None
    parsed = _parse_json_object(raw_body)
    if body_model is None:
        return parsed, None
    try:
        validated = body_model.model_validate(parsed)
    except ValidationError:
        raise BodyValidationError("request body failed validation") from None
    return validated.model_dump(mode="python"), validated


def _parse_json_object(raw_body: bytes | None) -> Mapping[str, object]:
    if raw_body is None:
        raise RequestDataError("request body is unavailable")
    try:
        parsed = strict_loads(raw_body)
    except ValueError:
        # Includes DuplicateKeyError: parsers disagree on duplicates, so they are never accepted.
        raise RequestDataError("request body is not strict JSON") from None
    if not isinstance(parsed, dict):
        raise RequestDataError("request body must be a JSON object")
    return parsed


def _query_data(request: HttpRequest) -> dict[str, object]:
    query: object = request.GET
    data: dict[str, object] = {}
    for key in _keys(query):
        values: object = query.getlist(key)  # type: ignore[attr-defined] # Django QueryDict
        if not isinstance(values, list) or len(values) != 1:
            raise RequestDataError("query parameter appears more than once")
        data[key] = values[0]
    return data


def _keys(query: object) -> list[str]:
    if not isinstance(query, Mapping):  # pragma: no cover - QueryDict is always a mapping
        raise TypeError("request.GET is not a mapping")
    return [key for key in query if isinstance(key, str)]


def _merge(target: dict[str, object], source: Mapping[str, object], label: str) -> None:
    for key, value in source.items():
        if key in target:
            # Ambiguity about which value was authorized is an attack surface; refuse it.
            raise RequestDataError(f"{label} collides with another request field")
        target[key] = value
