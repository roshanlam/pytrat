"""Request and decision types, evaluator ports, and route lookup.

Route lookup is default-deny: a ``(method, path)`` with no matching policy raises
``POLICY_NOT_FOUND``. Paths match exactly, or against simple ``{param}`` templates where a
parameter matches exactly one non-empty path segment. An exact path takes precedence over a
template; two templates that could match the same path are rejected at compile time, so lookup is
always unambiguous.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Final, Protocol, Self

from pytrat.core.binding import BindingResult
from pytrat.core.errors import AuthorizationError, ReasonCode
from pytrat.core.validation import VerifiedToken
from pytrat.policy._errors import PolicyFieldError

if TYPE_CHECKING:
    from pytrat.policy.compiler import CompiledPolicy

__all__ = [
    "HTTP_METHODS",
    "AgentDirectory",
    "AuthorizationRequest",
    "Decision",
    "PolicyEvaluator",
    "PolicySet",
    "RouteTemplate",
]

HTTP_METHODS: Final = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
"""Methods a policy may name. RFC 9110 §9.1: method names are case-sensitive."""

_PARAMETER: Final = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
# RFC 3986 §3.3 pchar, without braces (reserved here for templates).
_LITERAL: Final = re.compile(r"[A-Za-z0-9\-._~%!$&'()*+,;=:@]+")


def _empty_mapping() -> Mapping[str, object]:
    return MappingProxyType({})


@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    """Everything a policy needs to decide one request.

    Attributes:
        token: The verified Transaction Token, or None if the request carried none.
        caller: The authenticated workload identity of the immediate caller, or None if the
            caller could not be authenticated. A Transaction Token is not authentication
            (CLAUDE.md invariant 8); this value must come from mTLS, a workload JWT or similar.
        request_data: The validated request parameters compared against ``tctx``.
        operation: Optional operation label for correlation. It is not an authorization input.
    """

    token: VerifiedToken | None
    caller: str | None
    request_data: Mapping[str, object] = field(default_factory=_empty_mapping)
    operation: str | None = None


@dataclass(frozen=True, slots=True)
class Decision:
    """The outcome of evaluating one policy.

    Attributes:
        allowed: True only if every check passed.
        reason: The reason for a denial; None when allowed.
        policy_id: The policy that made the decision.
        binding: Which ``tctx`` fields were checked, when allowed and a transaction was required.
    """

    allowed: bool
    reason: ReasonCode | None
    policy_id: str
    binding: BindingResult | None = None

    def __post_init__(self) -> None:
        if self.allowed != (self.reason is None):
            raise ValueError("a decision is allowed exactly when it has no reason")


class AgentDirectory(Protocol):
    """Registry of known agents, consulted when a policy sets ``require_verified_agent``."""

    def is_registered(self, agent_id: str) -> bool:
        """Return True only if ``agent_id`` is a registered agent.

        Raises:
            DependencyError: If the directory cannot answer (the request is denied).
        """
        ...


class PolicyEvaluator(Protocol):
    """A per-route authorization decision point.

    :class:`~pytrat.policy.CompiledPolicy` is the built-in implementation. An external engine
    (OPA, AuthZEN) can be adapted to this protocol without changing callers.
    """

    def evaluate(self, request: AuthorizationRequest) -> Decision:
        """Return a decision; a denial is a ``Decision`` with ``allowed=False``."""
        ...

    def enforce(self, request: AuthorizationRequest) -> Decision:
        """Return an allowing decision or raise the ``PyTraTError`` for the first failed check."""
        ...


@dataclass(frozen=True, slots=True)
class RouteTemplate:
    """A validated ``(method, path)`` pattern.

    Attributes:
        method: Upper-case HTTP method.
        path: The path as configured.
        segments: Path segments; ``None`` marks a ``{param}`` segment.
    """

    method: str
    path: str
    segments: tuple[str | None, ...]

    @classmethod
    def parse(cls, method: str, path: str) -> Self:
        """Validate and compile a route.

        Raises:
            ConfigurationError: If the method is not a known HTTP method or the path is malformed.
        """
        if method not in HTTP_METHODS:
            raise PolicyFieldError(
                "method", f"must be one of {', '.join(sorted(HTTP_METHODS))} (upper case)"
            )
        if not path.startswith("/"):
            raise PolicyFieldError("path", "must start with '/'")
        segments: list[str | None] = []
        names: set[str] = set()
        for raw_segment in _split(path):
            if parameter := _PARAMETER.fullmatch(raw_segment):
                if parameter.group(1) in names:
                    raise PolicyFieldError("path", "repeats a template parameter name")
                names.add(parameter.group(1))
                segments.append(None)
            elif _LITERAL.fullmatch(raw_segment):
                segments.append(raw_segment)
            else:
                raise PolicyFieldError(
                    "path",
                    "has an empty or invalid segment; parameters must be a whole segment "
                    "like '{name}'",
                )
        return cls(method, path, tuple(segments))

    @property
    def is_exact(self) -> bool:
        """True if the path has no parameters."""
        return None not in self.segments

    def matches(self, segments: Sequence[str]) -> bool:
        """Return True if the concrete path ``segments`` match this template."""
        # A parameter matches exactly one non-empty segment; "//" never satisfies it.
        return len(segments) == len(self.segments) and all(
            (actual != "") if expected is None else expected == actual
            for expected, actual in zip(self.segments, segments, strict=True)
        )

    def overlaps(self, other: RouteTemplate) -> bool:
        """Return True if some concrete path could match both templates."""
        return (
            self.method == other.method
            and len(self.segments) == len(other.segments)
            and all(
                mine is None or theirs is None or mine == theirs
                for mine, theirs in zip(self.segments, other.segments, strict=True)
            )
        )


def _split(path: str) -> list[str]:
    # "/" is the root and has no segments; every other path keeps empty segments so they fail.
    return [] if path == "/" else path[1:].split("/")


type _TemplateIndex = Mapping[str, tuple[tuple[RouteTemplate, CompiledPolicy], ...]]


@dataclass(frozen=True, slots=True)
class PolicySet:
    """An immutable, compiled set of route policies. Build with :meth:`build` or the loader.

    Attributes:
        trust_domain: The Trust Domain the policy document declares, if any.
        routes: Every ``(route, policy)`` pair, in configuration order.
    """

    trust_domain: str | None
    routes: tuple[tuple[RouteTemplate, CompiledPolicy], ...]
    _exact: Mapping[tuple[str, str], CompiledPolicy] = field(repr=False, compare=False)
    _templates: _TemplateIndex = field(repr=False, compare=False)

    @classmethod
    def build(
        cls,
        routes: Iterable[tuple[str, str, CompiledPolicy]],
        *,
        trust_domain: str | None = None,
    ) -> Self:
        """Compile ``(method, path, policy)`` triples into a lookup structure.

        Raises:
            ConfigurationError: On an invalid method or path, a duplicate ``(method, path)``,
                overlapping templates, or a duplicate ``policy_id``. The error's ``index`` names
                the offending entry.
        """
        compiled: list[tuple[RouteTemplate, CompiledPolicy]] = []
        exact: dict[tuple[str, str], CompiledPolicy] = {}
        templates: dict[str, list[tuple[RouteTemplate, CompiledPolicy]]] = {}
        seen_ids: set[str] = set()
        for index, (method, path, policy) in enumerate(routes):
            try:
                route = RouteTemplate.parse(method, path)
            except PolicyFieldError as exc:
                raise PolicyFieldError(exc.field, exc.message, index=index) from None
            if policy.policy_id in seen_ids:
                raise PolicyFieldError("name", "duplicate resource name", index=index)
            seen_ids.add(policy.policy_id)
            if route.is_exact:
                if (method, path) in exact:
                    raise PolicyFieldError("path", f"duplicate route {method} {path}", index=index)
                exact[method, path] = policy
            else:
                for other, _ in templates.get(method, ()):
                    if route.overlaps(other):
                        raise PolicyFieldError(
                            "path",
                            f"route {method} {path} overlaps {method} {other.path}",
                            index=index,
                        )
                templates.setdefault(method, []).append((route, policy))
            compiled.append((route, policy))
        return cls(
            trust_domain=trust_domain,
            routes=tuple(compiled),
            _exact=MappingProxyType(exact),
            _templates=MappingProxyType({m: tuple(entries) for m, entries in templates.items()}),
        )

    def for_route(self, method: str, path: str) -> CompiledPolicy:
        """Return the policy for a request route.

        Raises:
            AuthorizationError: ``POLICY_NOT_FOUND`` if no policy matches (default deny).
        """
        policy = self._exact.get((method, path))
        if policy is not None:
            return policy
        if path.startswith("/"):
            segments = _split(path)
            for route, candidate in self._templates.get(method, ()):
                if route.matches(segments):
                    return candidate
        raise AuthorizationError(ReasonCode.POLICY_NOT_FOUND, "no policy matches the route")

    def __len__(self) -> int:
        return len(self.routes)
