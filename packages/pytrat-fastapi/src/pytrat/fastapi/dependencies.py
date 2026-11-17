"""The ``require_transaction`` dependency and its startup-time policy resolution.

A :class:`TransactionDependency` is created by :meth:`PyTraT.require_transaction
<pytrat.fastapi.PyTraT.require_transaction>`. At startup, :meth:`PyTraT.prepare
<pytrat.fastapi.PyTraT.prepare>` resolves, for every route that uses it, one
:class:`~pytrat.policy.CompiledPolicy` per HTTP method and a reader for the route's validated
request data. Per request the dependency only looks those up and runs the shared
:class:`~pytrat.policy.TransactionEnforcer` pipeline.
"""

from __future__ import annotations

import dataclasses
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from typing import Final

from starlette.requests import Request

from pytrat.client.context import bind_transaction
from pytrat.client.jwks import AsyncJwksRefresher
from pytrat.core.constants import TXN_TOKEN_HEADER
from pytrat.core.crypto import peek_header
from pytrat.core.errors import AuthorizationError, ConfigurationError, PyTraTError, ReasonCode
from pytrat.core.validation import TokenVerifier
from pytrat.core.workload import InboundRequest
from pytrat.fastapi._request_data import RequestDataReader
from pytrat.fastapi._routes import RouteView, route_path
from pytrat.fastapi.responses import MalformedRequestError, marker_of
from pytrat.policy import (
    CompiledPolicy,
    PolicySet,
    RouteTemplate,
    Transaction,
    TransactionEnforcer,
)

__all__ = ["TransactionDependency", "inbound_request"]

_EMPTY: Final[Mapping[str, object]] = {}
_BINDING_REASONS: Final = frozenset(
    {ReasonCode.TRANSACTION_CONTEXT_MISMATCH, ReasonCode.TRANSACTION_CONTEXT_MISSING}
)


def inbound_request(request: Request) -> InboundRequest:
    """Convert a Starlette request into the transport facts the enforcer needs.

    Every header is kept as sent, duplicates included, so a repeated ``Txn-Token`` is detected.
    """
    peer = request.client.host if request.client is not None else None
    return InboundRequest(tuple(request.headers.items()), peer)


@dataclass(frozen=True, slots=True)
class Engine:
    """Runtime collaborators shared by every dependency of one ``PyTraT`` instance."""

    enforcer: TransactionEnforcer
    policy_set: PolicySet | None
    verifier: TokenVerifier | None
    jwks: AsyncJwksRefresher | None


@dataclass(frozen=True, slots=True)
class PreparedRoute:
    """What one route needs per request, compiled at startup."""

    view: RouteView
    policies: Mapping[str, CompiledPolicy]
    reader: RequestDataReader | None


type RouteShapes = frozenset[tuple[str, tuple[str | None, ...]]]


class TransactionDependency:
    """FastAPI dependency that authorizes a request and yields its :class:`Transaction`.

    While the request is handled the verified token is bound with
    :func:`pytrat.client.context.bind_transaction`, so a
    :class:`~pytrat.client.AsyncTransactionClient` propagates it unchanged.

    Raises (per request, rendered as problem+json by the installed handler):
        TokenError, AuthenticationError, AuthorizationError, DependencyError: From the
            enforcement pipeline.
        MalformedRequestError: If the bound request data fails validation.
        ConfigurationError: If the route was not prepared at startup.
    """

    __slots__ = ("_engine", "_explicit_id", "_inline", "_operation", "_policy_id", "_prepared")

    def __init__(
        self,
        engine: Engine,
        *,
        inline: CompiledPolicy | None,
        policy_id: str | None,
        operation: str | None,
    ) -> None:
        self._engine = engine
        self._inline = inline
        self._policy_id = policy_id
        self._explicit_id = policy_id is not None
        self._operation = operation
        self._prepared: Mapping[int, tuple[PreparedRoute, ...]] = {}

    @property
    def engine(self) -> Engine:
        """The runtime collaborators of the ``PyTraT`` instance that created this dependency."""
        return self._engine

    def __repr__(self) -> str:
        mode = "inline" if self._inline else ("policy_id" if self._policy_id else "route")
        return f"TransactionDependency(mode={mode!r}, policy_id={self._policy_id!r})"

    async def __call__(self, request: Request) -> AsyncIterator[Transaction]:
        """Authorize the request, then keep its transaction bound until the response is done."""
        marker = marker_of(request.scope)
        marker.engaged = True
        prepared = self._lookup(request)
        policy = prepared.policies.get(request.method)
        if policy is None:
            raise AuthorizationError(
                ReasonCode.POLICY_NOT_FOUND, "no policy for this request method"
            )
        malformed: MalformedRequestError | None = None
        request_data = _EMPTY
        if prepared.reader is not None and policy.binding.rules:
            try:
                request_data = await prepared.reader.read(request)
            except MalformedRequestError as error:
                malformed = error
        inbound = inbound_request(request)
        await self._refresh_keys(inbound)
        transaction = self._enforce(policy, inbound, request_data, malformed)
        if transaction is None:  # prepare() only accepts policies that require a transaction
            raise ConfigurationError("policy does not require a transaction")
        marker.transaction_id = transaction.id
        with bind_transaction(transaction.token):
            yield transaction

    def _enforce(
        self,
        policy: CompiledPolicy,
        inbound: InboundRequest,
        request_data: Mapping[str, object],
        malformed: MalformedRequestError | None,
    ) -> Transaction | None:
        # Invalid request data is reported only after the token and the caller have been
        # checked: it then fails binding (audited as a denial) and the client is told
        # REQUEST_MALFORMED rather than which bound value is missing.
        try:
            return self._engine.enforcer.enforce(
                policy, inbound, request_data, operation=self._operation
            )
        except AuthorizationError as error:
            if malformed is None or error.reason not in _BINDING_REASONS:
                raise
            malformed.transaction_id = error.transaction_id
            raise malformed from None

    def _lookup(self, request: Request) -> PreparedRoute:
        route = request.scope.get("route")
        candidates = [c for c in self._prepared.get(id(route), ()) if c.view.route is route]
        if len(candidates) > 1:
            # The same route object included under several prefixes: pick by path.
            path = route_path(request.scope)
            candidates = [c for c in candidates if c.view.path_regex.match(path)]
        if len(candidates) != 1:
            raise ConfigurationError(
                "route was not prepared; run PyTraT.lifespan or PyTraT.prepare(app) at startup"
            )
        return candidates[0]

    async def _refresh_keys(self, inbound: InboundRequest) -> None:
        jwks, verifier = self._engine.jwks, self._engine.verifier
        if jwks is None or verifier is None:
            return
        try:
            raw_token = inbound.single(TXN_TOKEN_HEADER)
            if raw_token is None:
                return
            # Only the kid is read, to decide whether the trusted key set needs a refresh.
            header = peek_header(raw_token, max_bytes=verifier.settings.max_token_bytes)
            await jwks.refresh(force=jwks.keys.get(header.kid) is None)
        except PyTraTError:
            # Nothing here can allow a request: the enforcer verifies the token next and
            # reports (and audits) any failure.
            return

    def prepare(self, view: RouteView, *, shapes: RouteShapes) -> None:
        """Resolve and validate the policies for one route that uses this dependency.

        Args:
            view: The route.
            shapes: ``(method, segments)`` of every HTTP route in the application, used to
                decide whether a partially overlapping YAML route is served by another route.

        Raises:
            ConfigurationError: If no policy can be resolved, inline and YAML policies disagree,
                a policy does not require a transaction, or a bound field is not a parameter of
                the route.
        """
        if view.kind != "http" or view.dependant is None:
            raise ConfigurationError(
                f"{view.label}: require_transaction supports HTTP API routes only"
            )
        policies = {method: self._resolve(method, view, shapes) for method in view.methods}
        reader: RequestDataReader | None = None
        if any(policy.binding.rules for policy in policies.values()):
            reader = RequestDataReader.for_route(
                view.dependant, embed_body_fields=view.embed_body_fields, label=view.label
            )
        for policy in policies.values():
            _check_policy(policy, reader, view.label)
        entry = PreparedRoute(view=view, policies=policies, reader=reader)
        key = id(view.route)
        kept = tuple(
            existing
            for existing in self._prepared.get(key, ())
            if existing.view.route is not view.route or existing.view.path != view.path
        )
        self._prepared = {**self._prepared, key: (*kept, entry)}

    def _resolve(self, method: str, view: RouteView, shapes: RouteShapes) -> CompiledPolicy:
        label = f"{method} {view.path}"
        from_yaml = _yaml_policy(self._engine.policy_set, method, view, shapes)
        if self._inline is not None:
            default_id = from_yaml.policy_id if from_yaml else label
            inline = self._inline
            if not self._explicit_id:
                inline = dataclasses.replace(inline, policy_id=default_id)
            if from_yaml is None:
                return inline
            _require_agreement(inline, from_yaml, label)
            return from_yaml
        if self._policy_id is not None:
            policy = _policy_by_id(self._engine.policy_set, self._policy_id, label)
            if from_yaml is not None and from_yaml is not policy:
                raise ConfigurationError(
                    f"{label}: policy_id {self._policy_id!r} differs from the YAML policy "
                    f"{from_yaml.policy_id!r} for this route"
                )
            return policy
        if from_yaml is None:
            raise ConfigurationError(
                f"{label}: no inline policy and no YAML policy matches this route"
            )
        return from_yaml


def _check_policy(policy: CompiledPolicy, reader: RequestDataReader | None, label: str) -> None:
    if not policy.require_transaction:
        raise ConfigurationError(
            f"{label}: policy {policy.policy_id!r} does not require a transaction but the route "
            "uses require_transaction"
        )
    available = reader.names if reader is not None else frozenset()
    for rule in policy.binding.rules:
        if rule.request_path[0] not in available:
            raise ConfigurationError(
                f"{label}: bound field '{'.'.join(rule.request_path)}' is not a path, query or "
                "body field of the route"
            )


def _policy_by_id(policy_set: PolicySet | None, policy_id: str, label: str) -> CompiledPolicy:
    if policy_set is not None:
        for _, policy in policy_set.routes:
            if policy.policy_id == policy_id:
                return policy
    raise ConfigurationError(f"{label}: no YAML policy named {policy_id!r}")


def _yaml_policy(
    policy_set: PolicySet | None, method: str, view: RouteView, shapes: RouteShapes
) -> CompiledPolicy | None:
    """The YAML policy whose route template is identical to the route's, if any.

    Raises:
        ConfigurationError: If a YAML route overlaps this route without being identical to it and
            no other application route has exactly that template, so requests the YAML author
            meant for it would be served under this route's policy.
    """
    if policy_set is None or view.catch_all:
        return None
    try:
        target = RouteTemplate.parse(method, view.path)
    except ConfigurationError:
        return None  # not expressible in YAML (e.g. "/{name}.json"), so nothing can match it
    match: CompiledPolicy | None = None
    for template, policy in policy_set.routes:
        if not template.overlaps(target):
            continue
        if template.segments == target.segments:
            match = policy
        elif (method, template.segments) not in shapes:
            raise ConfigurationError(
                f"{method} {view.path}: YAML route {template.method} {template.path} overlaps "
                "this route but no route in the application has exactly that template"
            )
    return match


def _require_agreement(inline: CompiledPolicy, from_yaml: CompiledPolicy, label: str) -> None:
    # Binding order is irrelevant; everything else must be equal. Evaluated under the YAML
    # document's assurance ordering, which is the one in force for this route.
    same_rules = frozenset(inline.binding.rules) == frozenset(from_yaml.binding.rules)
    comparable = dataclasses.replace(
        inline, binding=from_yaml.binding, assurance=from_yaml.assurance
    )
    if not same_rules or comparable != from_yaml:
        raise ConfigurationError(
            f"{label}: inline require_transaction arguments disagree with YAML policy "
            f"{from_yaml.policy_id!r}"
        )
