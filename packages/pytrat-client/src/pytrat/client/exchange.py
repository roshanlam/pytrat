"""Sans-IO token exchange: build requests to, and parse responses from, a Transaction Token Service.

Everything here is a pure function over values. The sync and async clients are thin shells that
send what :func:`build_issue_request` / :func:`build_replacement_request` produce and feed the reply
to :func:`parse_exchange_response`.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import ClassVar, Final
from urllib.parse import urlencode

from pytrat.core import strict_loads
from pytrat.core.constants import (
    EXCHANGE_RESPONSE_TOKEN_TYPE,
    GRANT_TYPE_TOKEN_EXCHANGE,
    TOKEN_TYPE_REFRESH_TOKEN,
    TOKEN_TYPE_TXN_TOKEN,
)
from pytrat.core.errors import AuthorizationError, PyTraTError, ReasonCode
from pytrat.core.scopes import Scope
from pytrat.core.secret import SecretToken
from pytrat.core.validation import VerifiedToken

__all__ = [
    "MAX_EXCHANGE_RESPONSE_BYTES",
    "ExchangeError",
    "ExchangeRequest",
    "build_issue_request",
    "build_replacement_request",
    "check_replacement",
    "parse_exchange_response",
]

#: PyTraT profile: largest token-endpoint response accepted. Tokens are capped at 16 KiB by the
#: verifier; the rest is headroom for the JSON envelope.
MAX_EXCHANGE_RESPONSE_BYTES: Final = 64 * 1024

_FORM_CONTENT_TYPE: Final = "application/x-www-form-urlencoded"
_JSON_CONTENT_TYPE: Final = "application/json"
_MAX_OAUTH_ERROR: Final = 64
_MAX_OAUTH_DESCRIPTION: Final = 200
# RFC 6749 §5.2: error and error_description are limited to these characters.
_OAUTH_TEXT_INVALID: Final = re.compile(r"[^\x20\x21\x23-\x5B\x5D-\x7E]")
_OAUTH_ERROR_CODE: Final = re.compile(r"[\x20\x21\x23-\x5B\x5D-\x7E]+")
# PyTraT profile: anything long and token-shaped in a server's error text is redacted, so a TTS
# that echoes a credential back cannot leak it into our exceptions or logs.
_TOKEN_LIKE: Final = re.compile(r"[A-Za-z0-9_\-+/=.~]{32,}")
_REDACTED: Final = "[redacted]"


class ExchangeError(PyTraTError):
    """A token exchange was refused, failed, or produced a non-conforming response.

    Attributes:
        oauth_error: The RFC 6749 §5.2 ``error`` code from the TTS, sanitised, or None.
        oauth_error_description: The ``error_description``, sanitised, truncated and with anything
            token-shaped redacted, or None. Safe to log.
        status_code: The HTTP status of the TTS response, or None if no response was involved.
    """

    http_status: ClassVar[int] = 502

    def __init__(
        self,
        detail: str,
        *,
        reason: ReasonCode = ReasonCode.EXCHANGE_FAILED,
        oauth_error: str | None = None,
        oauth_error_description: str | None = None,
        status_code: int | None = None,
    ) -> None:
        super().__init__(reason, detail)
        self.oauth_error = oauth_error
        self.oauth_error_description = oauth_error_description
        self.status_code = status_code


@dataclass(frozen=True, slots=True)
class ExchangeRequest:
    """A token-endpoint request body and headers, ready to send.

    The form carries the subject token and possibly a client assertion, so ``repr`` lists only the
    parameter names.
    """

    form: Mapping[str, str] = field(repr=False)
    headers: Mapping[str, str] = field(repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "form", MappingProxyType(dict(self.form)))
        object.__setattr__(self, "headers", MappingProxyType(dict(self.headers)))

    def with_form(self, updates: Mapping[str, str]) -> ExchangeRequest:
        """Return a copy with ``updates`` merged into the form."""
        return ExchangeRequest(form={**self.form, **updates}, headers=self.headers)

    def body(self) -> bytes:
        """The ``application/x-www-form-urlencoded`` body (txn-tokens-11 §11.1)."""
        return urlencode(dict(self.form)).encode("ascii")

    def __repr__(self) -> str:
        return f"ExchangeRequest(form_fields={sorted(self.form)})"


def _thaw(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_thaw(item) for item in value]
    return value


def _compact_json_object(value: Mapping[str, object], name: str) -> str:
    if not isinstance(value, Mapping):
        raise ExchangeError(f"{name} must be a JSON object")
    try:
        return json.dumps(
            _thaw(value), separators=(",", ":"), sort_keys=True, ensure_ascii=False, allow_nan=False
        )
    except (TypeError, ValueError):
        raise ExchangeError(f"{name} must be JSON-serialisable") from None


def _base_form(
    *,
    audience: str,
    scope: Scope,
    subject_token: SecretToken,
    subject_token_type: str,
    request_context: Mapping[str, object] | None,
    request_details: Mapping[str, object] | None,
) -> ExchangeRequest:
    # txn-tokens-11 §11.1: these six parameters are REQUIRED.
    form = {
        "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
        "requested_token_type": TOKEN_TYPE_TXN_TOKEN,
        "audience": audience,
        "scope": str(scope),
        "subject_token": subject_token.reveal(),
        "subject_token_type": subject_token_type,
    }
    # txn-tokens-11 §11.1: request_context / request_details are JSON objects, URL-encoded by the
    # form encoding (not base64).
    if request_context is not None:
        form["request_context"] = _compact_json_object(request_context, "request_context")
    if request_details is not None:
        form["request_details"] = _compact_json_object(request_details, "request_details")
    headers = {"Content-Type": _FORM_CONTENT_TYPE, "Accept": _JSON_CONTENT_TYPE}
    return ExchangeRequest(form=form, headers=headers)


def build_issue_request(
    *,
    audience: str,
    scope: Scope | str,
    subject_token: SecretToken,
    subject_token_type: str,
    request_context: Mapping[str, object] | None = None,
    request_details: Mapping[str, object] | None = None,
) -> ExchangeRequest:
    """Build an initial Transaction Token request (txn-tokens-11 §11.1).

    Args:
        audience: The Trust Domain the token is requested for.
        scope: Requested scope; a :class:`Scope` or a space-delimited string.
        subject_token: The inbound credential, kept wrapped until it is encoded.
        subject_token_type: RFC 8693 token type URN of ``subject_token``.
        request_context: Optional JSON object describing the request environment.
        request_details: Optional JSON object describing the transaction.

    Raises:
        ExchangeError: ``SUBJECT_TOKEN_INVALID`` for a refresh-token subject type or a missing
            type; ``EXCHANGE_FAILED`` if a context argument is not a JSON object.
        TokenError: ``CLAIM_INVALID`` if ``scope`` is empty or not RFC 6749 syntax.
    """
    if not audience:
        raise ExchangeError("audience must be a non-empty string")
    if not isinstance(subject_token, SecretToken):
        raise TypeError("subject_token must be a SecretToken")
    if not subject_token_type:
        raise ExchangeError(
            "subject_token_type must be a non-empty string", reason=ReasonCode.SUBJECT_TOKEN_INVALID
        )
    # txn-tokens-11 §11.2 / §13.3: a refresh token is never an acceptable subject token.
    if subject_token_type == TOKEN_TYPE_REFRESH_TOKEN:
        raise ExchangeError(
            "refresh tokens must not be exchanged for Transaction Tokens",
            reason=ReasonCode.SUBJECT_TOKEN_INVALID,
        )
    return _base_form(
        audience=audience,
        scope=Scope.coerce(scope),
        subject_token=subject_token,
        subject_token_type=subject_token_type,
        request_context=request_context,
        request_details=request_details,
    )


def build_replacement_request(
    current: VerifiedToken,
    *,
    scope: Scope | None = None,
    request_context: Mapping[str, object] | None = None,
    request_details: Mapping[str, object] | None = None,
) -> ExchangeRequest:
    """Build a replacement request presenting ``current`` as the subject token.

    txn-tokens-11 §13.15: replacement presents the Txn-Token as ``subject_token`` and MUST NOT
    expand authorization. The ``aud`` is carried over unchanged.

    Args:
        current: The verified token being replaced.
        scope: Requested scope; defaults to the current scope. Must be a subset of it.
        request_context: Optional JSON object describing the request environment.
        request_details: Optional JSON object describing the transaction.

    Raises:
        AuthorizationError: ``REPLACEMENT_WIDENS_AUTHORIZATION`` if ``scope`` is not a subset of
            the current scope. Raised before any I/O.
    """
    if not isinstance(current, VerifiedToken):
        raise TypeError("current must be a VerifiedToken")
    requested = current.claims.scope if scope is None else scope
    # txn-tokens-11 §13.6 / §13.15: the requested scope can never exceed the subject's scope.
    if not requested.issubset(current.claims.scope):
        raise AuthorizationError(
            ReasonCode.REPLACEMENT_WIDENS_AUTHORIZATION,
            "requested scope is not a subset of the current scope",
        )
    return _base_form(
        audience=current.claims.aud,
        scope=requested,
        subject_token=current.forwardable,
        # PyTraT profile P4: the replacement subject_token_type is the txn_token URN.
        subject_token_type=TOKEN_TYPE_TXN_TOKEN,
        request_context=request_context,
        request_details=request_details,
    )


def check_replacement(current: VerifiedToken, replacement: VerifiedToken) -> None:
    """Defence in depth: confirm a TTS-issued replacement only attenuates ``current``.

    CLAUDE.md invariant 5 / txn-tokens-11 §13.15: ``txn``, ``sub``, ``aud`` and ``act`` never change
    and scope never widens. Under the agent profile, ``originator`` never changes and ``hop_count``
    never falls.

    Raises:
        AuthorizationError: ``REPLACEMENT_WIDENS_AUTHORIZATION`` naming the violated property.
    """
    old, new = current.claims, replacement.claims
    for name in ("txn", "sub", "aud", "act"):
        if getattr(old, name) != getattr(new, name):
            raise AuthorizationError(
                ReasonCode.REPLACEMENT_WIDENS_AUTHORIZATION, f"replacement changed '{name}'"
            )
    if not new.scope.issubset(old.scope):
        raise AuthorizationError(
            ReasonCode.REPLACEMENT_WIDENS_AUTHORIZATION, "replacement widened 'scope'"
        )
    if old.agentic_ctx is not None:
        if new.agentic_ctx is None:
            raise AuthorizationError(
                ReasonCode.REPLACEMENT_WIDENS_AUTHORIZATION, "replacement dropped 'agentic_ctx'"
            )
        if new.agentic_ctx.originator != old.agentic_ctx.originator:
            raise AuthorizationError(
                ReasonCode.REPLACEMENT_WIDENS_AUTHORIZATION, "replacement changed 'originator'"
            )
        if new.agentic_ctx.chain_metadata.hop_count < old.agentic_ctx.chain_metadata.hop_count:
            raise AuthorizationError(
                ReasonCode.REPLACEMENT_WIDENS_AUTHORIZATION, "replacement lowered 'hop_count'"
            )


def _strict_json_object(body: bytes) -> dict[str, object] | None:
    try:
        document = strict_loads(body)
    except (ValueError, UnicodeDecodeError):
        return None
    return document if isinstance(document, dict) else None


def _redact(text: str, secrets: Iterable[SecretToken]) -> str:
    for secret in secrets:
        text = text.replace(secret.reveal(), _REDACTED)
    return _TOKEN_LIKE.sub(_REDACTED, text)


def _sanitise(value: object, limit: int, secrets: Iterable[SecretToken]) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    cleaned = _redact(_OAUTH_TEXT_INVALID.sub("?", value), secrets)
    return cleaned[:limit]


def _media_type(headers: Mapping[str, str]) -> str:
    for name, value in headers.items():
        if name.lower() == "content-type":
            return value.split(";", 1)[0].strip().lower()
    return ""


def response_too_large() -> ExchangeError:
    """The error the shells raise when a TTS response exceeds the size cap."""
    return ExchangeError("token endpoint response exceeds the size limit")


def _error_response(status: int, body: bytes, secrets: tuple[SecretToken, ...]) -> ExchangeError:
    # RFC 6749 §5.2: error responses are JSON objects with `error` and optional
    # `error_description`.
    document = _strict_json_object(body) or {}
    raw_error = document.get("error")
    oauth_error = None
    if isinstance(raw_error, str) and _OAUTH_ERROR_CODE.fullmatch(raw_error):
        oauth_error = _sanitise(raw_error, _MAX_OAUTH_ERROR, secrets)
    description = _sanitise(document.get("error_description"), _MAX_OAUTH_DESCRIPTION, secrets)
    detail = f"token exchange failed with HTTP {status}"
    if oauth_error is not None:
        detail += f" ({oauth_error})"
    return ExchangeError(
        detail,
        oauth_error=oauth_error,
        oauth_error_description=description,
        status_code=status,
    )


def parse_exchange_response(
    status: int,
    headers: Mapping[str, str],
    body: bytes,
    *,
    redact: Iterable[SecretToken] = (),
) -> SecretToken:
    """Parse a token-endpoint response into the issued (still unverified) Transaction Token.

    The returned token has NOT been verified; callers must verify it before use.

    Args:
        status: HTTP status code.
        headers: Response headers.
        body: Response body.
        redact: Secrets sent with the request; removed from any echoed error text.

    Raises:
        ExchangeError: ``EXCHANGE_FAILED`` for an RFC 6749 §5.2 error, an oversized or malformed
            body, or any violation of txn-tokens-11 §11.4.
    """
    secrets = tuple(redact)
    if len(body) > MAX_EXCHANGE_RESPONSE_BYTES:
        raise response_too_large()
    # RFC 6749 §5.1: success is exactly 200; anything else (including redirects) is an error.
    if status != 200:
        raise _error_response(status, body, secrets)
    if _media_type(headers) != _JSON_CONTENT_TYPE:
        raise ExchangeError("token endpoint response is not application/json", status_code=status)
    document = _strict_json_object(body)
    if document is None:
        raise ExchangeError("token endpoint response is not a strict JSON object", status_code=200)
    # txn-tokens-11 §11.4: the response MUST NOT include a refresh token.
    if "refresh_token" in document:
        raise ExchangeError("token endpoint response contains a refresh_token", status_code=200)
    # txn-tokens-11 §11.4: token_type is "N_A" (RFC 8693 §2.2.1: compared case-insensitively).
    token_type = document.get("token_type")
    if not isinstance(token_type, str) or token_type.upper() != EXCHANGE_RESPONSE_TOKEN_TYPE:
        raise ExchangeError("token endpoint response token_type is not N_A", status_code=200)
    # txn-tokens-11 §11.4: issued_token_type is the txn_token URN.
    if document.get("issued_token_type") != TOKEN_TYPE_TXN_TOKEN:
        raise ExchangeError(
            "token endpoint response issued_token_type is not txn_token", status_code=200
        )
    access_token = document.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise ExchangeError("token endpoint response has no access_token string", status_code=200)
    return SecretToken(access_token)
