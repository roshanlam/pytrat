"""Binding request parameters to the authorized transaction context (``tctx``).

A Transaction Token's ``tctx`` records what was authorized ("transfer 10000 USD minor units to
account-B"). A :class:`ContextBinding` checks that the operation actually being performed matches
it, so a compromised intermediary cannot silently change the parameters.

Comparison is strict and canonical (CLAUDE.md invariant 9):

* types must match exactly: ``True != 1``, ``1 != "1"``;
* floats are rejected in bound positions, so money must be integer minor units;
* strings are compared after Unicode NFC normalisation, with no trimming or case folding;
* lists compare element-wise in order, objects key-wise, recursively;
* a missing value on either side is a denial.

Legitimate transformations between services are declared explicitly with :class:`Derived`; there
is no implicit coercion.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Self

from pytrat.core.errors import AuthorizationError, ConfigurationError, ReasonCode, TokenError

type Path = tuple[str, ...]
type Transform = Callable[[object], object]

_MISSING: Final = object()
_MAX_DEPTH: Final = 32


class UnbindableValueError(Exception):
    """A value contains a type that cannot be compared canonically."""


@dataclass(frozen=True, slots=True)
class Derived:
    """An explicit, audited mapping from a request value to a ``tctx`` value.

    Attributes:
        request_path: Dotted path in the request data.
        tctx_path: Dotted path in ``tctx``.
        transform: Pure function applied to the canonical request value before comparison.
        name: Stable name recorded in audit events.
    """

    request_path: str
    tctx_path: str
    transform: Transform
    name: str


@dataclass(frozen=True, slots=True)
class BindingRule:
    """One compiled comparison."""

    request_path: Path
    tctx_path: Path
    transform: Transform | None = None
    transform_name: str | None = None

    @property
    def label(self) -> str:
        """The ``tctx`` path as a dotted string (safe to log)."""
        return ".".join(self.tctx_path)


@dataclass(frozen=True, slots=True)
class BindingResult:
    """Outcome of a successful binding check, for audit details."""

    checked: tuple[str, ...]
    transforms: tuple[str, ...]


type BindingSpec = Sequence[str | Derived] | Mapping[str, str]


def _parse_path(dotted: str) -> Path:
    parts = tuple(dotted.split("."))
    if not dotted or any(not part for part in parts):
        raise ConfigurationError(f"invalid binding path {dotted!r}")
    return parts


@dataclass(frozen=True, slots=True)
class ContextBinding:
    """A compiled set of request ↔ ``tctx`` comparisons. Compile once at startup."""

    rules: tuple[BindingRule, ...]

    @classmethod
    def compile(cls, spec: BindingSpec) -> Self:
        """Compile a binding specification.

        Args:
            spec: Either a sequence of field paths (identical on both sides) and
                :class:`Derived` rules, or a mapping of request path to ``tctx`` path.

        Raises:
            ConfigurationError: If a path is malformed or a ``tctx`` path is bound twice.
        """
        rules: list[BindingRule] = []
        if isinstance(spec, Mapping):
            rules.extend(
                BindingRule(_parse_path(request), _parse_path(tctx))
                for request, tctx in spec.items()
            )
        else:
            for item in spec:
                if isinstance(item, Derived):
                    if not item.name:
                        raise ConfigurationError("derived bindings must be named")
                    rules.append(
                        BindingRule(
                            _parse_path(item.request_path),
                            _parse_path(item.tctx_path),
                            item.transform,
                            item.name,
                        )
                    )
                else:
                    path = _parse_path(item)
                    rules.append(BindingRule(path, path))
        targets = [rule.tctx_path for rule in rules]
        if len(set(targets)) != len(targets):
            raise ConfigurationError("a tctx path is bound more than once")
        return cls(tuple(rules))

    @property
    def fields(self) -> tuple[str, ...]:
        """The bound ``tctx`` paths."""
        return tuple(rule.label for rule in self.rules)

    def check(
        self, tctx: Mapping[str, object] | None, request_data: Mapping[str, object]
    ) -> BindingResult:
        """Verify the request matches the authorized context.

        Raises:
            AuthorizationError: ``TRANSACTION_CONTEXT_MISSING`` if ``tctx`` or a bound ``tctx``
                value is absent; ``TRANSACTION_CONTEXT_MISMATCH`` if a request value is absent,
                unbindable or different. The detail names the path, never the values.
            TokenError: ``CLAIM_INVALID`` if a bound ``tctx`` value contains a float or other
                unbindable type.
        """
        if not self.rules:
            return BindingResult(checked=(), transforms=())
        if tctx is None:
            raise AuthorizationError(
                ReasonCode.TRANSACTION_CONTEXT_MISSING, "token carries no transaction context"
            )
        transforms: list[str] = []
        for rule in self.rules:
            self._check_rule(rule, tctx, request_data)
            if rule.transform_name:
                transforms.append(rule.transform_name)
        return BindingResult(checked=self.fields, transforms=tuple(transforms))

    @staticmethod
    def _check_rule(
        rule: BindingRule, tctx: Mapping[str, object], request_data: Mapping[str, object]
    ) -> None:
        authorized = _resolve(tctx, rule.tctx_path)
        if authorized is _MISSING:
            raise AuthorizationError(
                ReasonCode.TRANSACTION_CONTEXT_MISSING, f"tctx has no value for '{rule.label}'"
            )
        try:
            authorized = canonical(authorized)
        except UnbindableValueError:
            raise TokenError(
                ReasonCode.CLAIM_INVALID, f"tctx value for '{rule.label}' cannot be bound"
            ) from None

        requested = _resolve(request_data, rule.request_path)
        if requested is _MISSING:
            raise _mismatch(rule, "request has no value")
        try:
            requested = canonical(requested)
            if rule.transform is not None:
                requested = canonical(rule.transform(requested))
        except (UnbindableValueError, ValueError, TypeError, KeyError, ArithmeticError):
            # A transform that cannot handle its input fails closed.
            raise _mismatch(rule, "request value cannot be bound") from None
        if not strict_equal(authorized, requested):
            raise _mismatch(rule, "request value differs from the authorized value")


def _mismatch(rule: BindingRule, why: str) -> AuthorizationError:
    return AuthorizationError(ReasonCode.TRANSACTION_CONTEXT_MISMATCH, f"'{rule.label}': {why}")


def _resolve(data: Mapping[str, object], path: Path) -> object:
    current: object = data
    for part in path:
        if not isinstance(current, Mapping) or part not in current:
            return _MISSING
        current = current[part]
    return current


def canonical(value: object) -> object:
    """Return the canonical comparison form of a JSON-like value.

    Raises:
        UnbindableValueError: If the value contains a float or a non-JSON type, two object keys
            that are equal after NFC normalisation, or nesting deeper than 32 levels.
    """
    return _canonical(value, 0)


def _canonical(value: object, depth: int) -> object:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return int(value)  # IntEnum and other int subclasses compare as int
    if isinstance(value, str):
        return unicodedata.normalize("NFC", str(value))
    # PyTraT profile: bound values nest at most _MAX_DEPTH levels, so hostile request bodies
    # fail the binding instead of exhausting the interpreter stack.
    if depth >= _MAX_DEPTH:
        raise UnbindableValueError
    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise UnbindableValueError
            normalised_key = unicodedata.normalize("NFC", key)
            if normalised_key in result:
                # Two keys that compare equal are ambiguous: the service may read the one the
                # check never compared (e.g. precomposed "é" vs "e" + combining acute).
                raise UnbindableValueError
            result[normalised_key] = _canonical(item, depth + 1)
        return result
    if isinstance(value, list | tuple):
        return [_canonical(item, depth + 1) for item in value]
    # Floats (ambiguous for money), bytes, Decimals, datetimes and objects are not bindable.
    raise UnbindableValueError


def strict_equal(left: object, right: object) -> bool:
    """Compare canonical values with exact type equality at every level."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        assert isinstance(right, dict)  # noqa: S101 - narrowing; types are identical
        return left.keys() == right.keys() and all(strict_equal(left[k], right[k]) for k in left)
    if isinstance(left, list):
        assert isinstance(right, list)  # noqa: S101 - narrowing; types are identical
        return len(left) == len(right) and all(map(strict_equal, left, right))
    return left == right
