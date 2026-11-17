"""Compiled, immutable route policies.

A :class:`CompiledPolicy` is built once at startup, either from YAML (:func:`compile_policy`) or
programmatically (:meth:`CompiledPolicy.build`). Both paths run the same validation, so an inline
FastAPI declaration and a YAML resource with the same settings produce equal policies.

Evaluation order is fixed and the first failure wins, so audit reasons are stable:

1. transaction required and present (``TOKEN_MISSING``)
2. scope (``SCOPE_INSUFFICIENT``)
3. caller (``WORKLOAD_UNAUTHENTICATED``, ``CALLER_NOT_ALLOWED``)
4. context binding (``TRANSACTION_CONTEXT_MISSING``, ``TRANSACTION_CONTEXT_MISMATCH``)
5. agent constraints (``AGENT_CONTEXT_MISSING``, ``AGENT_HOP_LIMIT_EXCEEDED``,
   ``AGENT_ASSURANCE_INSUFFICIENT``, ``AGENT_NOT_ALLOWED``, ``AGENT_UNVERIFIED``)
6. replay (``REPLAY_DETECTED``)

Replay is last so that a request denied for any other reason never consumes a single use.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Final, Self

from pytrat.core import BindingSpec, ContextBinding
from pytrat.core.assurance import AssuranceOrdering
from pytrat.core.claims import AgenticContext, TransactionClaims
from pytrat.core.errors import (
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    DependencyError,
    PyTraTError,
    ReasonCode,
    TokenError,
)
from pytrat.core.replay import ReplayStore, replay_key
from pytrat.core.scopes import Scope
from pytrat.core.validation import MAX_LEEWAY, VerifiedToken
from pytrat.policy._errors import PolicyFieldError
from pytrat.policy.evaluator import AgentDirectory, AuthorizationRequest, Decision, PolicySet
from pytrat.policy.model import AgentsModel, PolicyDocument, ResourceModel

__all__ = [
    "SUPPORTED_VERSIONS",
    "AgentRequirements",
    "CompiledPolicy",
    "check_version",
    "compile_policy",
]

SUPPORTED_VERSIONS: Final = frozenset({1})

# Programmatic argument names that differ from their YAML key.
_YAML_KEYS: Final = {"policy_id": "name"}


def _check_names(field_name: str, names: frozenset[str] | None) -> None:
    if names is None:
        return
    if not names:
        raise PolicyFieldError(field_name, "must not be empty; omit it to allow any")
    # Runtime check for untyped callers; the annotation alone does not guarantee it.
    entries: frozenset[object] = names
    if any(not isinstance(name, str) or not name for name in entries):
        raise PolicyFieldError(field_name, "entries must be non-empty strings")


def _to_names(field_name: str, value: Iterable[str] | None) -> frozenset[str] | None:
    if value is None or isinstance(value, frozenset):
        return value
    if isinstance(value, str):
        raise PolicyFieldError(field_name, "must be a list of names, not a single string")
    return frozenset(value)


@dataclass(frozen=True, slots=True)
class AgentRequirements:
    """Resource-side constraints on agent-mediated requests (agent-profile-03 §3.5).

    Attributes:
        enabled: Apply agent constraints. When False, ``agentic_ctx`` is neither required nor
            rejected, and every other attribute must keep its default.
        maximum_hops: Deny when ``chain_metadata.hop_count`` exceeds this.
        minimum_assurance: Deny when ``chain_metadata.min_assurance_level`` is below this level,
            absent, or unknown.
        require_chain_replacement: Recorded for the TTS and audit; not enforced here.
        require_agent_context: Deny requests whose token carries no ``agentic_ctx``.
        require_verified_agent: Deny unless the originator and proximate agent are registered in
            the configured :class:`~pytrat.policy.AgentDirectory`.
        allowed_originators: If set, the originator agent id must be one of these.

    ``session_id`` is never an input (agent-profile-03 §3.5.4).

    Raises:
        ConfigurationError: On construction, if a value is invalid or constraints are set while
            ``enabled`` is False.
    """

    enabled: bool = False
    maximum_hops: int | None = None
    minimum_assurance: str | None = None
    require_chain_replacement: bool = False
    require_agent_context: bool = False
    require_verified_agent: bool = False
    allowed_originators: frozenset[str] | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "allowed_originators",
            _to_names("agents.allowed_originators", self.allowed_originators),
        )
        _check_names("agents.allowed_originators", self.allowed_originators)
        hops: object = self.maximum_hops
        if hops is not None and (isinstance(hops, bool) or not isinstance(hops, int) or hops < 1):
            raise PolicyFieldError("agents.maximum_hops", "must be a positive integer")
        if self.minimum_assurance == "":
            raise PolicyFieldError("agents.minimum_assurance", "must not be empty")
        # PyTraT profile: constraints on a disabled block would be silently ignored, which reads
        # as protection that is not there. Fail loudly instead.
        constrained = (
            self.maximum_hops is not None
            or self.minimum_assurance is not None
            or self.require_chain_replacement
            or self.require_agent_context
            or self.require_verified_agent
            or self.allowed_originators is not None
        )
        if not self.enabled and constrained:
            raise PolicyFieldError(
                "agents.enabled", "agent constraints are set but agents.enabled is false"
            )


_NO_AGENTS: Final = AgentRequirements()
_DEFAULT_ASSURANCE: Final = AssuranceOrdering()


@dataclass(frozen=True, slots=True)
class CompiledPolicy:
    """An immutable authorization policy for one route.

    Build with :meth:`build` (or load from YAML); direct construction runs the same cross-field
    checks but does not normalise inputs.

    Attributes:
        policy_id: Stable identifier recorded in decisions and audit events.
        allowed_scopes: The token scope must contain at least one of these.
        binding: Request ↔ ``tctx`` comparisons.
        allowed_callers: If set, the authenticated caller must be one of these.
        require_transaction: Require a Transaction Token. When False, only the caller is checked.
        require_workload_identity: Require an authenticated caller.
        single_use: Reject a second use of the same ``txn`` for this policy.
        agents: Agent constraints.
        assurance: Ordering used to compare assurance levels.
        replay_store: Required when ``single_use`` is set.
        agent_directory: Required when ``agents.require_verified_agent`` is set.
    """

    policy_id: str
    allowed_scopes: Scope | None
    binding: ContextBinding
    allowed_callers: frozenset[str] | None = None
    require_transaction: bool = True
    require_workload_identity: bool = True
    single_use: bool = False
    agents: AgentRequirements = _NO_AGENTS
    assurance: AssuranceOrdering = _DEFAULT_ASSURANCE
    replay_store: ReplayStore | None = field(default=None, repr=False, compare=False)
    agent_directory: AgentDirectory | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self.policy_id:
            raise PolicyFieldError("policy_id", "must not be empty")
        _check_names("allowed_callers", self.allowed_callers)
        if self.require_transaction:
            if self.allowed_scopes is None:
                raise PolicyFieldError(
                    "allowed_scopes", "must not be empty when require_transaction is true"
                )
        else:
            self._check_transactionless()
        if not self.require_workload_identity and self.allowed_callers is not None:
            raise PolicyFieldError(
                "allowed_callers", "cannot be combined with require_workload_identity: false"
            )
        if self.agents.minimum_assurance is not None and not self.assurance.is_known(
            self.agents.minimum_assurance
        ):
            raise PolicyFieldError(
                "agents.minimum_assurance", "is not a level in the assurance ordering"
            )
        # Fail closed at startup: a missing dependency must never turn into an open route.
        if self.single_use and self.replay_store is None:
            raise PolicyFieldError(
                "single_use", "requires a replay store", ReasonCode.DEPENDENCY_UNAVAILABLE
            )
        if self.agents.require_verified_agent and self.agent_directory is None:
            raise PolicyFieldError(
                "agents.require_verified_agent",
                "requires an agent directory",
                ReasonCode.DEPENDENCY_UNAVAILABLE,
            )

    def _check_transactionless(self) -> None:
        # PyTraT profile: without a required transaction there is no token to check, so any
        # token-dependent setting would be silently ignored. Reject it instead.
        for field_name, is_set in (
            ("allowed_scopes", self.allowed_scopes is not None),
            ("bind_context", bool(self.binding.rules)),
            ("single_use", self.single_use),
            ("agents.enabled", self.agents.enabled),
        ):
            if is_set:
                raise PolicyFieldError(field_name, "requires require_transaction: true")

    @classmethod
    def build(
        cls,
        *,
        policy_id: str,
        allowed_scopes: Scope | str | Iterable[str] = (),
        bind_context: ContextBinding | BindingSpec = (),
        allowed_callers: Iterable[str] | None = None,
        require_transaction: bool = True,
        require_workload_identity: bool = True,
        single_use: bool = False,
        agents: AgentRequirements | None = None,
        assurance: AssuranceOrdering | None = None,
        replay_store: ReplayStore | None = None,
        agent_directory: AgentDirectory | None = None,
    ) -> Self:
        """Normalise inputs and build a validated policy.

        Args:
            policy_id: Stable policy identifier.
            allowed_scopes: A :class:`Scope`, a space-delimited string, or scope tokens.
            bind_context: Field paths, a request-path → ``tctx``-path mapping, or a compiled
                :class:`ContextBinding`.
            allowed_callers: Permitted workload identities; None allows any authenticated caller.
            require_transaction: Require a Transaction Token.
            require_workload_identity: Require an authenticated caller.
            single_use: Enable replay protection for this policy.
            agents: Agent constraints; None disables them.
            assurance: Assurance ordering; defaults to ``unverified < low < medium < high``.
            replay_store: Required when ``single_use`` is True.
            agent_directory: Required when ``agents.require_verified_agent`` is True.

        Raises:
            ConfigurationError: If any compile-time check fails. ``DEPENDENCY_UNAVAILABLE`` if a
                required replay store or agent directory is missing; ``POLICY_INVALID`` otherwise.
        """
        return cls(
            policy_id=policy_id,
            allowed_scopes=_compile_scopes(allowed_scopes),
            binding=_compile_binding(bind_context),
            allowed_callers=_to_names("allowed_callers", allowed_callers),
            require_transaction=require_transaction,
            require_workload_identity=require_workload_identity,
            single_use=single_use,
            agents=agents or _NO_AGENTS,
            assurance=assurance or _DEFAULT_ASSURANCE,
            replay_store=replay_store,
            agent_directory=agent_directory,
        )

    def evaluate(self, request: AuthorizationRequest) -> Decision:
        """Decide ``request`` without raising for a denial.

        Returns:
            An allowing :class:`Decision`, or a denying one whose ``reason`` is the first failed
            check. Errors that are not ``PyTraTError`` (bugs) propagate.
        """
        try:
            return self.enforce(request)
        except PyTraTError as exc:
            return Decision(allowed=False, reason=exc.reason, policy_id=self.policy_id)

    def enforce(self, request: AuthorizationRequest) -> Decision:
        """Decide ``request``, raising on denial.

        Raises:
            PyTraTError: For the first failed check, in the order documented in this module.
        """
        if not self.require_transaction:
            self._check_caller(request.caller)
            return Decision(allowed=True, reason=None, policy_id=self.policy_id)
        claims = _require_token(request.token).claims
        self._check_scope(claims.scope)
        self._check_caller(request.caller)
        binding = self.binding.check(claims.tctx, request.request_data)
        self._check_agents(claims.agentic_ctx)
        self._check_replay(claims)
        return Decision(allowed=True, reason=None, policy_id=self.policy_id, binding=binding)

    def _check_scope(self, scope: Scope) -> None:
        if self.allowed_scopes is None or self.allowed_scopes.intersection(scope) is None:
            raise AuthorizationError(
                ReasonCode.SCOPE_INSUFFICIENT, "token scope does not include an allowed scope"
            )

    def _check_caller(self, caller: str | None) -> None:
        if not self.require_workload_identity:
            return
        if not caller:
            raise AuthenticationError(
                ReasonCode.WORKLOAD_UNAUTHENTICATED, "caller workload is not authenticated"
            )
        if self.allowed_callers is not None and caller not in self.allowed_callers:
            raise AuthorizationError(
                ReasonCode.CALLER_NOT_ALLOWED, "caller workload is not allowed for this resource"
            )

    def _check_agents(self, agentic_ctx: AgenticContext | None) -> None:
        agents = self.agents
        if not agents.enabled:
            return
        if agentic_ctx is None:
            # Any constraint *about* the agent chain is unsatisfiable without one; only a hop
            # limit is met by a chain of zero agents. (Security review finding #2.)
            if (
                agents.require_agent_context
                or agents.require_verified_agent
                or agents.minimum_assurance is not None
                or agents.allowed_originators is not None
            ):
                raise AuthorizationError(
                    ReasonCode.AGENT_CONTEXT_MISSING, "token carries no agentic_ctx"
                )
            return
        chain = agentic_ctx.chain_metadata
        if agents.maximum_hops is not None and chain.hop_count > agents.maximum_hops:
            raise AuthorizationError(
                ReasonCode.AGENT_HOP_LIMIT_EXCEEDED, "agent chain exceeds the maximum hop count"
            )
        if agents.minimum_assurance is not None and not self.assurance.satisfies(
            chain.min_assurance_level, agents.minimum_assurance
        ):
            raise AuthorizationError(
                ReasonCode.AGENT_ASSURANCE_INSUFFICIENT,
                "agent chain assurance is below the required level",
            )
        if (
            agents.allowed_originators is not None
            and agentic_ctx.originator.id not in agents.allowed_originators
        ):
            raise AuthorizationError(
                ReasonCode.AGENT_NOT_ALLOWED, "originating agent is not allowed for this resource"
            )
        if agents.require_verified_agent:
            self._check_registered(agentic_ctx)

    def _check_registered(self, agentic_ctx: AgenticContext) -> None:
        directory = self.agent_directory
        if directory is None:
            raise DependencyError("agent directory is not configured")
        for agent_id in (agentic_ctx.originator.id, agentic_ctx.proximate_agent.id):
            # Anything but an explicit True is a denial.
            if directory.is_registered(agent_id) is not True:
                raise AuthorizationError(ReasonCode.AGENT_UNVERIFIED, "agent is not registered")

    def _check_replay(self, claims: TransactionClaims) -> None:
        if not self.single_use:
            return
        if self.replay_store is None:
            raise DependencyError("replay store is not configured")
        # PyTraT profile P8: one use per (txn, policy) until the token expires. A verifier accepts
        # the token until ``exp + leeway``, so the record outlives the largest allowed leeway.
        retain_until = float(claims.exp) + MAX_LEEWAY.total_seconds()
        self.replay_store.record_once(replay_key(claims.txn, self.policy_id), retain_until)


def _require_token(token: VerifiedToken | None) -> VerifiedToken:
    if token is None:
        raise TokenError(ReasonCode.TOKEN_MISSING, "a transaction token is required")
    return token


def _compile_scopes(value: Scope | str | Iterable[str]) -> Scope | None:
    if isinstance(value, Scope):
        return value
    if isinstance(value, str):
        value = value.split(" ") if value else ()
    tokens = frozenset(value)
    if not tokens:
        return None
    try:
        return Scope(tokens)
    except TokenError:
        raise PolicyFieldError(
            "allowed_scopes", "contains a value that is not a valid scope-token"
        ) from None


def _compile_binding(spec: ContextBinding | BindingSpec) -> ContextBinding:
    if isinstance(spec, ContextBinding):
        return spec
    if isinstance(spec, str):
        raise PolicyFieldError("bind_context", "must be a list of paths, not a single string")
    try:
        return ContextBinding.compile(spec)
    except ConfigurationError as exc:
        raise PolicyFieldError("bind_context", exc.detail) from None


def check_version(version: int, source: str) -> None:
    """Reject unsupported policy document versions.

    Raises:
        ConfigurationError: If ``version`` is not supported.
    """
    if version not in SUPPORTED_VERSIONS:
        supported = ", ".join(str(v) for v in sorted(SUPPORTED_VERSIONS))
        raise ConfigurationError(
            f"{source}: version: unsupported policy version (supported: {supported})"
        )


def _agent_requirements(model: AgentsModel | None) -> AgentRequirements | None:
    if model is None:
        return None
    return AgentRequirements(
        enabled=model.enabled,
        maximum_hops=model.maximum_hops,
        minimum_assurance=model.minimum_assurance,
        require_chain_replacement=model.require_chain_replacement,
        require_agent_context=model.require_agent_context,
        require_verified_agent=model.require_verified_agent,
        allowed_originators=_to_names("agents.allowed_originators", model.allowed_originators),
    )


def _compile_resource(
    resource: ResourceModel,
    assurance: AssuranceOrdering,
    replay_store: ReplayStore | None,
    agent_directory: AgentDirectory | None,
) -> CompiledPolicy:
    return CompiledPolicy.build(
        policy_id=resource.name,
        allowed_scopes=resource.allowed_scopes,
        bind_context=resource.bind_context,
        allowed_callers=resource.allowed_callers,
        require_transaction=resource.require_transaction,
        require_workload_identity=resource.require_workload_identity,
        single_use=resource.single_use,
        agents=_agent_requirements(resource.agents),
        assurance=assurance,
        replay_store=replay_store,
        agent_directory=agent_directory,
    )


def _ordering(document: PolicyDocument, source: str) -> AssuranceOrdering:
    if document.assurance_levels is None:
        return _DEFAULT_ASSURANCE
    try:
        return AssuranceOrdering(document.assurance_levels)
    except ConfigurationError as exc:
        raise ConfigurationError(f"{source}: assurance_levels: {exc.detail}") from None


def compile_policy(
    document: PolicyDocument,
    *,
    source: str = "<policy>",
    expected_trust_domain: str | None = None,
    replay_store: ReplayStore | None = None,
    agent_directory: AgentDirectory | None = None,
) -> PolicySet:
    """Compile a validated policy document.

    Args:
        document: The parsed document.
        source: Label used as the prefix of error messages (usually the file name).
        expected_trust_domain: If set, the document's ``trust_domain`` must equal it.
        replay_store: Store for ``single_use`` resources.
        agent_directory: Directory for ``require_verified_agent`` resources.

    Raises:
        ConfigurationError: With ``"<source>: <dotted.location>: <problem>"`` for the first
            failed compile-time check.
    """
    check_version(document.version, source)
    if expected_trust_domain is not None and document.trust_domain != expected_trust_domain:
        raise ConfigurationError(
            f"{source}: trust_domain: does not match the configured trust domain"
        )
    assurance = _ordering(document, source)
    routes: list[tuple[str, str, CompiledPolicy]] = []
    try:
        for index, resource in enumerate(document.resources):
            try:
                policy = _compile_resource(resource, assurance, replay_store, agent_directory)
            except PolicyFieldError as exc:
                raise PolicyFieldError(exc.field, exc.message, exc.reason, index=index) from None
            routes.append((resource.method, resource.path, policy))
        return PolicySet.build(routes, trust_domain=document.trust_domain)
    except PolicyFieldError as exc:
        key = _YAML_KEYS.get(exc.field, exc.field)
        raise ConfigurationError(
            f"{source}: resources[{exc.index}].{key}: {exc.message}", exc.reason
        ) from None
