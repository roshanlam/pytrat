"""View decorators: ``@require_transaction`` and ``@exempt``."""

from __future__ import annotations

import functools
import inspect
from collections.abc import Awaitable, Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Final

from pydantic import BaseModel

from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest, HttpResponse
from pytrat.client.context import bind_transaction
from pytrat.core import ConfigurationError, PyTraTError, ReplayStore
from pytrat.django._http import inbound_request, problem_response, request_data
from pytrat.django._runtime import Runtime, get_runtime
from pytrat.policy import AgentDirectory, AgentRequirements, CompiledPolicy, Transaction

__all__ = ["TransactionGuard", "exempt", "guard_of", "is_exempt", "require_transaction"]

GUARD_ATTRIBUTE: Final = "pytrat_transaction_guard"
EXEMPT_ATTRIBUTE: Final = "pytrat_exempt"

type SyncView = Callable[..., HttpResponse]
type AsyncView = Callable[..., Awaitable[HttpResponse]]
type View = SyncView | AsyncView


@dataclass(frozen=True, slots=True)
class TransactionGuard:
    """The policy attached to one decorated view.

    Exactly one of ``policy`` (inline, compiled at decoration time) and ``policy_id`` (looked up
    in the YAML policy configured by ``PYTRAT['POLICY']``) is set.

    Attributes:
        policy: The inline policy.
        policy_id: The YAML resource name.
        body_model: Pydantic model the JSON body is validated against, if any.
        operation: Operation name passed to the policy (used by agent constraints).
    """

    policy: CompiledPolicy | None
    policy_id: str | None
    body_model: type[BaseModel] | None = field(default=None)
    operation: str | None = None

    def resolve(self, runtime: Runtime) -> CompiledPolicy:
        """The policy to enforce.

        Raises:
            ImproperlyConfigured: If ``policy_id`` names a resource that is not in the YAML
                policy, or no YAML policy is configured. Fails closed: the view never runs.
        """
        if self.policy is not None:
            return self.policy
        if runtime.policies is None:
            raise ImproperlyConfigured(
                f"view uses policy_id={self.policy_id!r} but PYTRAT['POLICY'] is not set"
            )
        for _, candidate in runtime.policies.routes:
            if candidate.policy_id == self.policy_id:
                return candidate
        raise ImproperlyConfigured(f"policy_id={self.policy_id!r} is not in PYTRAT['POLICY']")

    def authorize(self, request: HttpRequest, url_kwargs: dict[str, object]) -> Transaction | None:
        """Run the enforcement pipeline for ``request`` and attach the results to it.

        Sets ``request.transaction`` (and ``request.validated_body`` when ``body_model`` is set).

        Raises:
            PyTraTError: Any denial, from request-data parsing or the enforcer.
            ImproperlyConfigured: The integration or this view's policy is misconfigured.
        """
        runtime = get_runtime()
        policy = self.resolve(runtime)
        data, validated = request_data(request, url_kwargs, policy, self.body_model)
        transaction = runtime.enforcer.enforce(
            policy, inbound_request(request), data, operation=self.operation
        )
        request.transaction = transaction
        if self.body_model is not None:
            request.validated_body = validated
        return transaction


def require_transaction(
    *,
    scope: str | Iterable[str] | None = None,
    bind_fields: Sequence[str] | Mapping[str, str] = (),
    allowed_callers: Iterable[str] | None = None,
    require_workload_identity: bool = True,
    single_use: bool = False,
    agents: AgentRequirements | None = None,
    policy_id: str | None = None,
    body_model: type[BaseModel] | None = None,
    operation: str | None = None,
    replay_store: ReplayStore | None = None,
    agent_directory: AgentDirectory | None = None,
) -> Callable[[View], View]:
    """Require an authorized Transaction Token for a Django view (sync or async).

    Inline arguments compile to a :class:`CompiledPolicy` once, at decoration time; alternatively
    ``policy_id`` names a resource in the YAML policy (``PYTRAT['POLICY']``). Per request the
    decorator builds request data (strict JSON body, URL kwargs and query parameters; a name in two
    sources is a 400), runs the configured :class:`TransactionEnforcer`, sets
    ``request.transaction`` and binds the token while the view runs so outbound
    ``TransactionClient`` calls propagate it. Any :class:`PyTraTError`, including one the view
    raises, becomes an RFC 9457 problem response.

    Args:
        scope: Allowed scopes (space-delimited string or tokens). Required unless ``policy_id``.
        bind_fields: Request fields bound to ``tctx`` (paths, or a request-path → tctx-path map).
        allowed_callers: Permitted calling workloads; None allows any authenticated caller.
        require_workload_identity: Require an authenticated calling workload.
        single_use: Reject reuse of the same ``txn``; requires ``replay_store``.
        agents: Agent constraints.
        policy_id: Use this YAML resource instead of inline arguments.
        body_model: Validate the JSON body with this Pydantic model, expose the instance as
            ``request.validated_body`` and bind its ``model_dump(mode="python")``.
        operation: Operation name passed to the policy.
        replay_store: Replay store for ``single_use``.
        agent_directory: Directory for ``agents.require_verified_agent``.

    Raises:
        ImproperlyConfigured: At decoration time, if both inline arguments and ``policy_id`` are
            given, neither is, or the inline policy fails compilation.
    """
    inline_given = (
        scope is not None
        or bool(bind_fields)
        or allowed_callers is not None
        or not require_workload_identity
        or single_use
        or agents is not None
    )
    if policy_id is not None and inline_given:
        raise ImproperlyConfigured("pass either policy_id or inline policy arguments, not both")
    if policy_id is None and scope is None:
        raise ImproperlyConfigured("require_transaction needs scope= or policy_id=")

    def decorate(view: View) -> View:
        policy: CompiledPolicy | None = None
        if policy_id is None:
            try:
                policy = CompiledPolicy.build(
                    policy_id=_view_name(view),
                    allowed_scopes=scope or (),
                    bind_context=bind_fields,
                    allowed_callers=allowed_callers,
                    require_workload_identity=require_workload_identity,
                    single_use=single_use,
                    agents=agents,
                    replay_store=replay_store,
                    agent_directory=agent_directory,
                )
            except ConfigurationError as exc:
                raise ImproperlyConfigured(f"invalid transaction policy: {exc.detail}") from exc
        guard = TransactionGuard(
            policy=policy, policy_id=policy_id, body_model=body_model, operation=operation
        )
        result: View
        if inspect.iscoroutinefunction(view):
            result = _wrap_async(view, guard)
        else:
            result = _wrap_sync(view, guard)
        setattr(result, GUARD_ATTRIBUTE, guard)
        return result

    return decorate


def exempt[V: View](view: V) -> V:
    """Mark a view under a protected prefix as deliberately not requiring a transaction."""
    setattr(view, EXEMPT_ATTRIBUTE, True)
    return view


def guard_of(view: object) -> TransactionGuard | None:
    """The :class:`TransactionGuard` attached by ``@require_transaction``, if any."""
    guard = getattr(view, GUARD_ATTRIBUTE, None)
    return guard if isinstance(guard, TransactionGuard) else None


def is_exempt(view: object) -> bool:
    """Whether the view was marked with ``@exempt``."""
    return getattr(view, EXEMPT_ATTRIBUTE, False) is True


def _wrap_sync(view: SyncView, guard: TransactionGuard) -> SyncView:
    @functools.wraps(view)
    def wrapper(request: HttpRequest, *args: object, **kwargs: object) -> HttpResponse:
        debug = _debug_errors()
        try:
            transaction = guard.authorize(request, kwargs)
        except PyTraTError as error:
            return problem_response(error, debug=debug)
        with _bound(transaction):
            try:
                return view(request, *args, **kwargs)
            except PyTraTError as error:
                return problem_response(error, transaction_id=_txn_id(transaction), debug=debug)

    return wrapper


def _wrap_async(view: AsyncView, guard: TransactionGuard) -> AsyncView:
    # The enforcer does no I/O, so it runs inline rather than in a thread.
    @functools.wraps(view)
    async def wrapper(request: HttpRequest, *args: object, **kwargs: object) -> HttpResponse:
        debug = _debug_errors()
        try:
            transaction = guard.authorize(request, kwargs)
        except PyTraTError as error:
            return problem_response(error, debug=debug)
        with _bound(transaction):
            try:
                return await view(request, *args, **kwargs)
            except PyTraTError as error:
                return problem_response(error, transaction_id=_txn_id(transaction), debug=debug)

    return wrapper


@contextmanager
def _bound(transaction: Transaction | None) -> Iterator[None]:
    if transaction is None:
        yield
        return
    with bind_transaction(transaction.token):
        yield


def _txn_id(transaction: Transaction | None) -> str | None:
    return transaction.id if transaction is not None else None


def _view_name(view: object) -> str:
    module = getattr(view, "__module__", None) or "view"
    name = getattr(view, "__qualname__", None) or type(view).__qualname__
    return f"{module}.{name}"


def _debug_errors() -> bool:
    return get_runtime().settings.debug_errors
