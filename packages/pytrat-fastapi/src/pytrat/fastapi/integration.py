"""The :class:`PyTraT` facade: one object that wires PyTraT into a FastAPI application."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Iterable
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from pytrat.client.jwks import AsyncJwksRefresher
from pytrat.core.audit import AuditSink
from pytrat.core.binding import BindingSpec, ContextBinding
from pytrat.core.errors import ConfigurationError, PyTraTError
from pytrat.core.replay import ReplayStore
from pytrat.core.validation import TokenVerifier
from pytrat.core.workload import WorkloadAuthenticator
from pytrat.fastapi._routes import RouteView, could_match_prefix, iter_routes
from pytrat.fastapi.dependencies import Engine, TransactionDependency
from pytrat.fastapi.middleware import TransactionMiddleware
from pytrat.fastapi.responses import exception_handler
from pytrat.fastapi.settings import PyTraTSettings
from pytrat.policy import (
    AgentDirectory,
    AgentRequirements,
    CompiledPolicy,
    PolicySet,
    TransactionEnforcer,
    VerifyFunction,
)

if TYPE_CHECKING:
    from fastapi import FastAPI
    from fastapi.dependencies.models import Dependant

__all__ = ["PyTraT"]

_PROVISIONAL_ID = "inline"


class PyTraT:
    """Transaction Token enforcement for one FastAPI service.

    Typical wiring::

        pytrat = PyTraT(service="ledger", verifier=verifier, authenticator=authn,
                        audit=sink, protected_prefixes=("/internal",))
        app = FastAPI(lifespan=pytrat.lifespan)
        pytrat.install(app)

    Args:
        service: This service's name, recorded in audit events.
        verifier: A :class:`TokenVerifier` (or a function with the same contract).
        authenticator: Authenticates calling workloads. Without one, every policy that requires
            workload identity (the default) denies.
        policy: A YAML :class:`PolicySet` (from :func:`pytrat.policy.load_policy`).
        audit: Destination for audit events.
        protected_prefixes: Paths that must be guarded by ``require_transaction`` or exempt.
        replay_store: Required by inline ``single_use`` policies.
        agent_directory: Required by inline agent policies with ``require_verified_agent``.
        jwks_refresher: Refreshes the verifier's trusted keys; requires a :class:`TokenVerifier`
            whose key provider is ``jwks_refresher.keys``.
        debug: Include the failed check's description in error responses.

    Raises:
        ConfigurationError: If the configuration is invalid.
    """

    def __init__(
        self,
        *,
        service: str,
        verifier: TokenVerifier | VerifyFunction,
        authenticator: WorkloadAuthenticator | None = None,
        policy: PolicySet | None = None,
        audit: AuditSink | None = None,
        protected_prefixes: Iterable[str] = (),
        replay_store: ReplayStore | None = None,
        agent_directory: AgentDirectory | None = None,
        jwks_refresher: AsyncJwksRefresher | None = None,
        debug: bool = False,
    ) -> None:
        self._settings = PyTraTSettings(
            service=service, protected_prefixes=tuple(protected_prefixes), debug=debug
        )
        if jwks_refresher is not None and not isinstance(verifier, TokenVerifier):
            raise ConfigurationError("jwks_refresher requires verifier to be a TokenVerifier")
        self._engine = Engine(
            enforcer=TransactionEnforcer(
                service=service, verify=verifier, authenticator=authenticator, audit=audit
            ),
            policy_set=policy,
            verifier=verifier if isinstance(verifier, TokenVerifier) else None,
            jwks=jwks_refresher,
        )
        self._replay_store = replay_store
        self._agent_directory = agent_directory
        # id -> object; holding the object keeps its id from being reused.
        self._exempt: dict[int, object] = {}

    @property
    def settings(self) -> PyTraTSettings:
        """The validated settings."""
        return self._settings

    def require_transaction(
        self,
        *,
        scope: str | None = None,
        scopes: Iterable[str] | None = None,
        bind_fields: BindingSpec | ContextBinding | None = None,
        allowed_callers: Iterable[str] | None = None,
        require_workload_identity: bool | None = None,
        single_use: bool | None = None,
        agents: AgentRequirements | None = None,
        policy_id: str | None = None,
        operation: str | None = None,
    ) -> TransactionDependency:
        """Create a dependency that authorizes the request and returns its ``Transaction``.

        Three ways to choose the policy:

        * inline: pass ``scope``/``scopes`` (plus any of ``bind_fields``, ``allowed_callers``,
          ``require_workload_identity``, ``single_use``, ``agents``, ``policy_id``). Compiled
          now; if a YAML policy also exists for the route the two must agree.
        * ``policy_id`` alone: the YAML resource with that name.
        * no arguments: the YAML resource whose ``(method, path)`` equals the route template.

        ``bind_fields`` name path parameters, query parameters and body fields of the route; the
        values compared with ``tctx`` are the validated values the handler receives.

        Args:
            scope: One allowed scope.
            scopes: Several allowed scopes (the token needs at least one).
            bind_fields: Field paths, a request-path to ``tctx``-path mapping, ``Derived`` rules,
                or a compiled ``ContextBinding``.
            allowed_callers: Permitted calling workloads.
            require_workload_identity: Require an authenticated caller (default True).
            single_use: Reject a second use of the same ``txn`` (needs ``replay_store``).
            agents: Agent constraints.
            policy_id: Policy name for audit and replay keys, or the YAML policy to use.
            operation: Correlation label passed to the enforcer (not an authorization input).

        Raises:
            ConfigurationError: Immediately, if the inline arguments are invalid or incomplete.
                Route-dependent problems are reported by :meth:`prepare` at startup.
        """
        inline: CompiledPolicy | None = None
        if scope is not None and scopes is not None:
            raise ConfigurationError("pass either scope or scopes, not both")
        allowed_scopes = (scope,) if scope is not None else scopes
        if allowed_scopes is not None:
            if isinstance(allowed_scopes, str):
                raise ConfigurationError("scopes must be a collection, not a single string")
            inline = CompiledPolicy.build(
                policy_id=policy_id or _PROVISIONAL_ID,
                allowed_scopes=tuple(allowed_scopes),
                bind_context=() if bind_fields is None else bind_fields,
                allowed_callers=allowed_callers,
                require_workload_identity=(
                    True if require_workload_identity is None else require_workload_identity
                ),
                single_use=bool(single_use),
                agents=agents,
                replay_store=self._replay_store,
                agent_directory=self._agent_directory,
            )
        elif any(
            value is not None
            for value in (
                bind_fields,
                allowed_callers,
                require_workload_identity,
                single_use,
                agents,
            )
        ):
            raise ConfigurationError(
                "inline policy arguments require scope or scopes; use policy_id alone to "
                "select a YAML policy"
            )
        return TransactionDependency(
            self._engine, inline=inline, policy_id=policy_id, operation=operation
        )

    def exempt[F: Callable[..., object]](self, endpoint: F) -> F:
        """Decorator: explicitly allow a handler under a protected prefix without a transaction."""
        self._exempt[id(endpoint)] = endpoint
        return endpoint

    def is_exempt(self, endpoint: object) -> bool:
        """True if ``endpoint`` was marked with :meth:`exempt`."""
        return endpoint is not None and self._exempt.get(id(endpoint)) is endpoint

    def install(self, app: FastAPI) -> None:
        """Register the problem+json error handler and the fail-closed middleware.

        Call before the application starts.
        """
        app.add_exception_handler(PyTraTError, exception_handler(debug=self._settings.debug))
        if self._settings.protected_prefixes:
            app.add_middleware(
                TransactionMiddleware, settings=self._settings, is_exempt=self.is_exempt
            )

    def prepare(self, app: FastAPI) -> None:
        """Compile every route's policy and check that protected prefixes are fully covered.

        Raises:
            ConfigurationError: On the first route that cannot be resolved, or if a route under a
                protected prefix is unguarded.
        """
        views = list(iter_routes(app.routes))
        shapes = frozenset(_shapes(views))
        for view in views:
            for dependency in self._dependencies_of(view):
                dependency.prepare(view, shapes=shapes)
        self._assert_covered(views)

    def unprotected_routes(self, app: FastAPI) -> tuple[str, ...]:
        """Routes under a protected prefix that neither require a transaction nor are exempt."""
        return self._unprotected(list(iter_routes(app.routes)))

    def assert_all_routes_covered(self, app: FastAPI) -> None:
        """Refuse an application with unguarded routes under a protected prefix.

        Raises:
            ConfigurationError: ``POLICY_NOT_FOUND``, listing every such route.
        """
        self._assert_covered(list(iter_routes(app.routes)))

    @asynccontextmanager
    async def lifespan(self, app: FastAPI) -> AsyncIterator[None]:
        """FastAPI lifespan: prepare routes, check coverage and load the trusted keys.

        Compose it with your own lifespan by entering ``pytrat.lifespan(app)`` inside it.
        """
        self.prepare(app)
        if self._engine.jwks is not None:
            await self._engine.jwks.refresh()
        yield

    def _assert_covered(self, views: list[RouteView]) -> None:
        unprotected = self._unprotected(views)
        if unprotected:
            raise ConfigurationError(
                "routes under a protected prefix neither require a transaction nor are exempt: "
                + ", ".join(unprotected)
            )

    def _unprotected(self, views: list[RouteView]) -> tuple[str, ...]:
        found: list[str] = []
        for view in views:
            protected = any(
                could_match_prefix(view, prefix) for prefix in self._settings.protected_prefixes
            )
            if not protected or self.is_exempt(view.endpoint):
                continue
            if view.kind == "http" and self._dependencies_of(view):
                continue
            found.append(view.label)
        return tuple(found)

    def _dependencies_of(self, view: RouteView) -> list[TransactionDependency]:
        if view.dependant is None:
            return []
        found: list[TransactionDependency] = []
        _collect(view.dependant, self._engine, found)
        return found


def _collect(dependant: Dependant, engine: Engine, found: list[TransactionDependency]) -> None:
    for sub in dependant.dependencies:
        call = sub.call
        if (
            isinstance(call, TransactionDependency)
            and call.engine is engine
            and all(call is not seen for seen in found)
        ):
            found.append(call)
        _collect(sub, engine, found)


def _shapes(views: list[RouteView]) -> Iterable[tuple[str, tuple[str | None, ...]]]:
    for view in views:
        if view.kind != "http":
            continue
        segments = tuple(
            None if "{" in segment else segment
            for segment in ([] if view.path == "/" else view.path[1:].split("/"))
        )
        for method in view.methods:
            yield method, segments
