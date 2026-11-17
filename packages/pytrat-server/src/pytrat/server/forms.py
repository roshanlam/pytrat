"""Parsing of the Txn-Token Request (txn-tokens-11 §11.1, RFC 8693 §2.1). Pure; no I/O.

The raw ``application/x-www-form-urlencoded`` body is turned into a typed :class:`TokenRequest`
exactly once. Anything ambiguous is rejected rather than interpreted:

* duplicate parameters (RFC 6749 §3.2: parameters "MUST NOT be included more than once");
* oversize bodies, a missing or wrong content type, non-ASCII or malformed encoding;
* ``request_context`` / ``request_details`` that are not strict JSON objects (duplicate keys,
  ``NaN`` and non-object values are rejected).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Final
from urllib.parse import parse_qsl

from pytrat.core import strict_loads
from pytrat.core.claims import JsonObject
from pytrat.core.constants import (
    GRANT_TYPE_TOKEN_EXCHANGE,
    TOKEN_TYPE_REFRESH_TOKEN,
    TOKEN_TYPE_TXN_TOKEN,
)
from pytrat.core.errors import ReasonCode, TokenError
from pytrat.core.scopes import Scope
from pytrat.core.secret import SecretToken
from pytrat.server.errors import OAuthError, OAuthErrorCode

__all__ = [
    "FORM_CONTENT_TYPE",
    "ClientAuthParams",
    "TokenRequest",
    "parse_json_object",
    "parse_token_request",
]

FORM_CONTENT_TYPE: Final = "application/x-www-form-urlencoded"

_MAX_FIELDS: Final = 32
_MAX_JSON_DEPTH: Final = 16
_REQUIRED: Final = (
    "grant_type",
    "requested_token_type",
    "audience",
    "scope",
    "subject_token",
    "subject_token_type",
)
# PyTraT profile: RFC 8693 parameters with semantics this TTS does not implement are refused
# rather than silently ignored, so a requester never believes delegation or targeting took effect.
_UNSUPPORTED: Final = frozenset({"actor_token", "actor_token_type", "resource"})


@dataclass(frozen=True, slots=True)
class ClientAuthParams:
    """Client-authentication parameters from the form body (RFC 7523 §2.2).

    Attributes:
        client_id: Optional ``client_id``.
        client_assertion_type: ``client_assertion_type`` if sent.
        client_assertion: The unverified assertion, wrapped so it never reaches logs.
    """

    client_id: str | None = None
    client_assertion_type: str | None = None
    client_assertion: SecretToken | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class TokenRequest:
    """A syntactically valid Txn-Token Request. Nothing in it is authenticated yet.

    Attributes:
        grant_type: Always the token-exchange grant (txn-tokens-11 §11.1).
        requested_token_type: Always ``urn:ietf:params:oauth:token-type:txn_token``.
        audience: Requested Trust Domain (checked later against configuration).
        scope: Requested scope.
        subject_token: The unverified subject token.
        subject_token_type: Its type URI (never the refresh-token type).
        request_context: Optional strict JSON object (txn-tokens-11 §11.1).
        request_details: Optional strict JSON object (txn-tokens-11 §11.1).
        client: Client-authentication parameters.
    """

    grant_type: str
    requested_token_type: str
    audience: str
    scope: Scope
    subject_token: SecretToken = field(repr=False)
    subject_token_type: str
    request_context: JsonObject | None = None
    request_details: JsonObject | None = None
    client: ClientAuthParams = field(default_factory=ClientAuthParams)

    @property
    def is_replacement(self) -> bool:
        """True if the subject token is a Txn-Token (txn-tokens-11 §13.15, PyTraT profile P4)."""
        return self.subject_token_type == TOKEN_TYPE_TXN_TOKEN


def _invalid(description: str, reason: ReasonCode = ReasonCode.TOKEN_MALFORMED) -> OAuthError:
    return OAuthError(OAuthErrorCode.INVALID_REQUEST, description, reason)


def _check_content_type(content_type: str | None) -> None:
    if content_type is None:
        raise _invalid("content type is required")
    media_type, _, raw_params = content_type.partition(";")
    if media_type.strip().lower() != FORM_CONTENT_TYPE:
        raise _invalid("content type must be application/x-www-form-urlencoded")
    for raw_param in raw_params.split(";"):
        name, _, value = raw_param.strip().partition("=")
        if name.lower() == "charset" and value.strip().strip('"').lower() != "utf-8":
            raise _invalid("only the utf-8 charset is supported")


def _decode_fields(raw_body: bytes) -> dict[str, str]:
    try:
        text = raw_body.decode("ascii")
        pairs = parse_qsl(
            text,
            keep_blank_values=True,
            strict_parsing=True,
            encoding="utf-8",
            errors="strict",
            max_num_fields=_MAX_FIELDS,
        )
    except (UnicodeDecodeError, ValueError):
        raise _invalid("request body is not valid form encoding") from None
    fields: dict[str, str] = {}
    for name, value in pairs:
        if name in fields:
            raise _invalid("request parameters must not be repeated")
        fields[name] = value
    return fields


def _freeze(value: object, depth: int) -> object:
    if depth > _MAX_JSON_DEPTH:
        raise ValueError("JSON nesting is too deep")
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item, depth + 1) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item, depth + 1) for item in value)
    return value


def parse_json_object(raw: str) -> JsonObject:
    """Strictly decode a JSON object into a deeply immutable mapping.

    Raises:
        ValueError: If ``raw`` is not a JSON object, contains duplicate keys, ``NaN`` /
            ``Infinity`` or nesting deeper than 16 levels.
    """
    try:
        value = strict_loads(raw)
    except RecursionError:
        raise ValueError("JSON nesting is too deep") from None
    if not isinstance(value, dict):
        raise ValueError("expected a JSON object")  # noqa: TRY004 - documented ValueError contract
    frozen = _freeze(value, 0)
    assert isinstance(frozen, Mapping)  # noqa: S101 - narrowing; _freeze preserves dicts
    return frozen


def _optional_object(fields: Mapping[str, str], name: str) -> JsonObject | None:
    raw = fields.get(name)
    if raw is None:
        return None
    try:
        return parse_json_object(raw)
    except ValueError:
        raise _invalid(f"{name} must be a JSON object", ReasonCode.CLAIM_INVALID) from None


def _required(fields: Mapping[str, str], name: str) -> str:
    value = fields.get(name)
    if not value:
        raise _invalid(f"parameter '{name}' is required", ReasonCode.CLAIM_MISSING)
    return value


def _client_params(fields: Mapping[str, str]) -> ClientAuthParams:
    if "client_secret" in fields:
        # PyTraT profile: shared secrets are not accepted; txn-tokens-11 §11.5 recommends
        # asymmetric methods and the TTS never holds workload secrets.
        raise OAuthError(
            OAuthErrorCode.INVALID_CLIENT,
            "client_secret authentication is not supported",
            ReasonCode.WORKLOAD_UNAUTHENTICATED,
        )
    raw_assertion = fields.get("client_assertion")
    return ClientAuthParams(
        client_id=fields.get("client_id") or None,
        client_assertion_type=fields.get("client_assertion_type") or None,
        client_assertion=SecretToken(raw_assertion) if raw_assertion else None,
    )


def _check_grant(fields: Mapping[str, str]) -> None:
    grant_type = _required(fields, "grant_type")
    # txn-tokens-11 §11.1: grant_type MUST be token-exchange.
    if grant_type != GRANT_TYPE_TOKEN_EXCHANGE:
        raise OAuthError(
            OAuthErrorCode.UNSUPPORTED_GRANT_TYPE,
            "grant_type must be token-exchange",
            ReasonCode.TOKEN_TYPE_INVALID,
        )
    # txn-tokens-11 §11.1: requested_token_type MUST be the txn_token URN.
    if _required(fields, "requested_token_type") != TOKEN_TYPE_TXN_TOKEN:
        raise _invalid("requested_token_type must be txn_token", ReasonCode.TOKEN_TYPE_INVALID)


def parse_token_request(
    raw_body: bytes, content_type: str | None, *, max_bytes: int
) -> TokenRequest:
    """Parse and validate a raw Txn-Token Request body.

    Args:
        raw_body: The undecoded request body.
        content_type: The ``Content-Type`` header value, if any.
        max_bytes: Maximum accepted body size.

    Returns:
        The typed request.

    Raises:
        OAuthError: ``invalid_request`` (413 for an oversize body) for malformed input, missing
            parameters, duplicates, a wrong ``requested_token_type`` or a refresh-token subject;
            ``unsupported_grant_type`` for a wrong ``grant_type``; ``invalid_scope`` for scope
            syntax errors; ``invalid_client`` if ``client_secret`` is sent.
    """
    if len(raw_body) > max_bytes:
        raise OAuthError(
            OAuthErrorCode.INVALID_REQUEST,
            "request body is too large",
            ReasonCode.TOKEN_MALFORMED,
            status=413,
        )
    _check_content_type(content_type)
    fields = _decode_fields(raw_body)
    _check_grant(fields)
    if unsupported := _UNSUPPORTED.intersection(fields):
        raise _invalid(f"parameter '{min(unsupported)}' is not supported")
    subject_token_type = _required(fields, "subject_token_type")
    # txn-tokens-11 §11.2, §13.3: refresh tokens MUST NOT be used to request Txn-Tokens.
    if subject_token_type == TOKEN_TYPE_REFRESH_TOKEN:
        raise _invalid(
            "refresh tokens cannot be used as subject tokens", ReasonCode.SUBJECT_TOKEN_INVALID
        )
    audience = _required(fields, "audience")
    try:
        scope = Scope.parse(_required(fields, "scope"))
    except TokenError:
        raise OAuthError(
            OAuthErrorCode.INVALID_SCOPE, "scope is not valid", ReasonCode.CLAIM_INVALID
        ) from None
    return TokenRequest(
        grant_type=GRANT_TYPE_TOKEN_EXCHANGE,
        requested_token_type=TOKEN_TYPE_TXN_TOKEN,
        audience=audience,
        scope=scope,
        subject_token=SecretToken(_required(fields, "subject_token")),
        subject_token_type=subject_token_type,
        request_context=_optional_object(fields, "request_context"),
        request_details=_optional_object(fields, "request_details"),
        client=_client_params(fields),
    )
