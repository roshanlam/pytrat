"""The Transaction Token bound to the current execution context.

Backed by a :class:`contextvars.ContextVar`, so each asyncio task and each thread started through
``contextvars.copy_context`` (as ``anyio.to_thread`` and ``asyncio.to_thread`` do) sees the value
that was bound when it was spawned, and a binding made inside one task never leaks into another.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

from pytrat.core.errors import ReasonCode, TokenError
from pytrat.core.validation import VerifiedToken

__all__ = ["bind_transaction", "current_transaction", "optional_transaction"]

_current: ContextVar[VerifiedToken | None] = ContextVar("pytrat_transaction", default=None)


@contextmanager
def bind_transaction(token: VerifiedToken) -> Iterator[VerifiedToken]:
    """Bind ``token`` as the current transaction for the duration of the ``with`` block.

    The previous binding (if any) is restored on exit, including on error.

    Raises:
        TypeError: If ``token`` is not a :class:`VerifiedToken`; only verified tokens can be bound.
    """
    if not isinstance(token, VerifiedToken):
        raise TypeError("only a VerifiedToken can be bound as the current transaction")
    reset_token = _current.set(token)
    try:
        yield token
    finally:
        _current.reset(reset_token)


def current_transaction() -> VerifiedToken:
    """Return the bound transaction.

    Raises:
        TokenError: ``TOKEN_MISSING`` if no transaction is bound.
    """
    token = _current.get()
    if token is None:
        raise TokenError(ReasonCode.TOKEN_MISSING, "no transaction is bound to this context")
    return token


def optional_transaction() -> VerifiedToken | None:
    """Return the bound transaction, or None if there is none."""
    return _current.get()
