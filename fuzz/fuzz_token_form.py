"""Fuzz the TTS token-endpoint form parser (``parse_token_request``).

Input layout: ``content-type byte || raw body``.

Invariants: only :class:`OAuthError` is raised; an accepted request has every required parameter,
never a refresh-token subject, and ``request_context``/``request_details`` that are JSON objects.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from urllib.parse import urlencode

from fuzz._harness import assert_no_token, choose, fuzz
from pytrat.core.constants import (
    GRANT_TYPE_TOKEN_EXCHANGE,
    TOKEN_TYPE_ACCESS_TOKEN,
    TOKEN_TYPE_REFRESH_TOKEN,
    TOKEN_TYPE_TXN_TOKEN,
)
from pytrat.server import OAuthError, parse_token_request

_CONTENT_TYPES: tuple[str | None, ...] = (
    "application/x-www-form-urlencoded",
    "application/x-www-form-urlencoded; charset=utf-8",
    'Application/X-WWW-Form-Urlencoded;charset="UTF-8"',
    "application/x-www-form-urlencoded; charset=latin-1",
    "application/json",
    None,
)
_MAX_BYTES = 32_768


def TestOneInput(data: bytes) -> None:  # noqa: N802 - name required by Atheris
    """Parse one raw form body."""
    content_type, body = choose(data, _CONTENT_TYPES)
    try:
        request = parse_token_request(body, content_type, max_bytes=_MAX_BYTES)
    except OAuthError as error:
        assert_no_token(error)
        return
    if request.grant_type != GRANT_TYPE_TOKEN_EXCHANGE:
        raise AssertionError("accepted a request with the wrong grant_type")
    if request.requested_token_type != TOKEN_TYPE_TXN_TOKEN:
        raise AssertionError("accepted a request for another token type")
    if request.subject_token_type == TOKEN_TYPE_REFRESH_TOKEN:
        raise AssertionError("accepted a refresh token as the subject")
    if not request.audience or not request.subject_token.reveal() or not request.scope:
        raise AssertionError("accepted a request without a required parameter")
    for value in (request.request_context, request.request_details):
        if value is not None and not isinstance(value, Mapping):
            raise AssertionError("accepted a request_context/request_details that is not an object")


def _form(**fields: str) -> bytes:
    base = {
        "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
        "requested_token_type": TOKEN_TYPE_TXN_TOKEN,
        "audience": "payments.internal",
        "scope": "payments.transfer",
        "subject_token": "opaque-subject",
        "subject_token_type": TOKEN_TYPE_ACCESS_TOKEN,
        **fields,
    }
    return urlencode({name: value for name, value in base.items() if value != "<drop>"}).encode()


def seeds() -> Iterator[bytes]:
    """A valid request and every class of rejection."""
    yield bytes([0]) + _form()
    yield bytes([1]) + _form(request_details='{"amount_minor": 10000}')
    yield bytes([0]) + _form(request_context='{"a": 1, "a": 2}')
    yield bytes([0]) + _form(request_details="[1, 2]")
    yield bytes([0]) + _form(request_details='{"n": NaN}')
    yield bytes([0]) + _form(request_details='{"n": 1e400}')
    yield bytes([0]) + _form(subject_token_type=TOKEN_TYPE_REFRESH_TOKEN)
    yield bytes([0]) + _form(grant_type="client_credentials")
    yield bytes([0]) + _form(scope="<drop>")
    yield bytes([0]) + _form(actor_token="x")
    yield bytes([0]) + _form(client_secret="s")
    yield bytes([0]) + _form(client_assertion_type="x", client_assertion="y", client_id="c")
    yield bytes([0]) + _form() + b"&audience=other"
    yield bytes([0]) + b"%zz=1"
    yield bytes([3]) + _form()
    yield bytes([4]) + b"{}"


if __name__ == "__main__":
    fuzz(TestOneInput)
