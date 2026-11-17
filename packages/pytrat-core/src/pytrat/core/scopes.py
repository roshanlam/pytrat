"""The ``scope`` value type.

txn-tokens-11 §11.1: scope is a space-delimited list of case-sensitive strings (RFC 6749 §3.3).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Self

from pytrat.core.errors import ReasonCode, TokenError

# RFC 6749 §3.3: scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
_SCOPE_TOKEN = re.compile(r"[\x21\x23-\x5B\x5D-\x7E]+")


@dataclass(frozen=True, slots=True)
class Scope:
    """An immutable set of scope tokens.

    Construct with :meth:`parse` for wire values or :meth:`of` for literals. Both validate the
    RFC 6749 grammar and reject empty scopes.
    """

    tokens: frozenset[str]

    def __post_init__(self) -> None:
        if not self.tokens:
            raise TokenError(ReasonCode.CLAIM_INVALID, "scope must contain at least one value")
        for token in self.tokens:
            if not _SCOPE_TOKEN.fullmatch(token):
                raise TokenError(ReasonCode.CLAIM_INVALID, "scope contains an invalid scope-token")

    @classmethod
    def parse(cls, raw: str) -> Self:
        """Parse a space-delimited scope string.

        Raises:
            TokenError: ``CLAIM_INVALID`` if the value is empty or not RFC 6749 scope syntax.
        """
        if not isinstance(raw, str):
            raise TokenError(ReasonCode.CLAIM_INVALID, "scope must be a string")
        # Strict: exactly one space between tokens, no leading/trailing whitespace.
        return cls(frozenset(raw.split(" ")) if raw else frozenset())

    @classmethod
    def of(cls, *tokens: str) -> Self:
        """Build a scope from individual tokens."""
        return cls(frozenset(tokens))

    @classmethod
    def coerce(cls, value: Scope | str | Iterable[str]) -> Scope:
        """Accept a :class:`Scope`, a space-delimited string, or an iterable of tokens."""
        if isinstance(value, Scope):
            return value
        if isinstance(value, str):
            return cls.parse(value)
        return cls(frozenset(value))

    def issubset(self, other: Scope) -> bool:
        """Return True if every token here is also in ``other``."""
        return self.tokens <= other.tokens

    def intersection(self, other: Scope) -> Scope | None:
        """Return the common tokens, or None if there are none."""
        common = self.tokens & other.tokens
        return Scope(common) if common else None

    def __contains__(self, token: object) -> bool:
        return token in self.tokens

    def __iter__(self) -> Iterator[str]:
        return iter(sorted(self.tokens))

    def __len__(self) -> int:
        return len(self.tokens)

    def __str__(self) -> str:
        """Canonical wire form: tokens sorted and space-separated."""
        return " ".join(sorted(self.tokens))
