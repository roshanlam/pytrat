"""Fuzz the client's token-endpoint response parser (``parse_exchange_response``).

Input layout: ``status byte || content-type byte || body``.

Invariants: only :class:`ExchangeError` is raised, never echoing a token from the response or
the request; an accepted response is a 200 ``application/json`` body with a non-empty token.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

from fuzz._harness import assert_no_token, choose, fuzz
from pytrat.client import ExchangeError, parse_exchange_response
from pytrat.core import SecretToken
from pytrat.core.constants import TOKEN_TYPE_TXN_TOKEN

_STATUSES = (200, 400, 401, 403, 429, 500, 503, 302)
_CONTENT_TYPES = ("application/json", "application/json; charset=utf-8", "text/html", "")
_SENT = SecretToken("subject-token-sent-by-the-client")


def TestOneInput(data: bytes) -> None:  # noqa: N802 - name required by Atheris
    """Parse one token-endpoint response."""
    status, rest = choose(data, _STATUSES)
    content_type, body = choose(rest, _CONTENT_TYPES)
    try:
        token = parse_exchange_response(
            status, {"Content-Type": content_type}, body, redact=(_SENT,)
        )
    except ExchangeError as error:
        assert_no_token(error)
        if _SENT.reveal() in str(error) or _SENT.reveal() in repr(error):
            raise AssertionError("an exchange error echoed the client's subject token") from None
        return
    if status != 200 or not content_type.startswith("application/json") or not token.reveal():
        raise AssertionError("accepted a response that is not a successful token response")


def seeds() -> Iterator[bytes]:
    """A valid response and RFC 6749 §5.2 / txn-tokens-11 §11.4 violations."""
    valid = {
        "access_token": "opaque.token.value",
        "issued_token_type": TOKEN_TYPE_TXN_TOKEN,
        "token_type": "N_A",
        "expires_in": 60,
    }
    yield bytes([0, 0]) + json.dumps(valid).encode()
    yield bytes([0, 1]) + json.dumps({**valid, "token_type": "n_a"}).encode()
    yield bytes([0, 0]) + json.dumps({**valid, "refresh_token": "r"}).encode()
    yield bytes([0, 0]) + json.dumps({**valid, "token_type": "Bearer"}).encode()
    yield bytes([0, 2]) + json.dumps(valid).encode()
    yield bytes([1, 0]) + b'{"error": "invalid_request", "error_description": "bad"}'
    yield (
        bytes([1, 0])
        + json.dumps(
            {"error": "invalid_grant", "error_description": f"echo {_SENT.reveal()}"}
        ).encode()
    )
    yield bytes([5, 0]) + b"<html>oops</html>"
    yield bytes([7, 0]) + b""


if __name__ == "__main__":
    fuzz(TestOneInput)
