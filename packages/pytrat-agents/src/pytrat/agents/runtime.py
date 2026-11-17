"""The trusted agent runtime: authorization and credential hygiene around LLM tool calls.

agent-profile-03 §3.7 splits an agent into an *inference layer* (the LLM) and an *infrastructure
layer* that executes tool calls and talks to the TTS. Token exchange "MUST NOT be exposed as a
tool" and credentials "MUST NOT appear in the LLM's context window". :class:`ToolRuntime` is the
infrastructure-layer piece:

- it obtains the current :class:`~pytrat.core.validation.VerifiedToken` from an injected provider
  (which may perform a replacement); the LLM never sees it and tools never receive it;
- before each call it checks scope and agent-chain requirements, then validates the arguments;
- it scans every tool result and refuses (or redacts) anything shaped like a compact JWS;
- :meth:`ToolRuntime.tool_specs` describes only the registered tools: no exchange, replacement or
  credential capability is ever listed.

**An in-process decorator is not an isolation boundary.** Code running in the same interpreter as
the runtime (including any code the model can influence, such as a code-execution tool) can read
the provider's memory, monkey-patch this module, or call the provider directly. The guarantees here
hold only if the inference layer cannot execute arbitrary code in this process. The recommended
deployment runs the runtime as a separate process or sidecar from the model (§3.7) and uses
out-of-band attestation to show that it did (§5.16).
"""

from __future__ import annotations

import functools
import inspect
import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, replace
from datetime import date, datetime, time
from decimal import Decimal
from enum import StrEnum
from types import MappingProxyType
from typing import ClassVar, Final, cast, get_type_hints
from uuid import UUID

from pydantic import BaseModel, ConfigDict, PydanticUserError, ValidationError, create_model

from pytrat.agents.policy import AgentRequirements, check_agent_requirements
from pytrat.agents.registry import AgentAttributeStore, AgentRecord
from pytrat.core.assurance import AssuranceOrdering
from pytrat.core.audit import AuditEvent, AuditSink, EventType
from pytrat.core.claims import TransactionClaims
from pytrat.core.errors import (
    AuthorizationError,
    ConfigurationError,
    DependencyError,
    PyTraTError,
    ReasonCode,
)
from pytrat.core.scopes import Scope
from pytrat.core.secret import SecretToken
from pytrat.core.validation import VerifiedToken

__all__ = [
    "REDACTED",
    "ResultMode",
    "TokenProvider",
    "ToolArgumentError",
    "ToolInvocation",
    "ToolResultBlockedError",
    "ToolRuntime",
    "ToolSpec",
    "find_token_like",
]

#: Replacement text used by :attr:`ResultMode.REDACT`.
REDACTED: Final = "[REDACTED:JWS]"

# A compact JWS (or the first three segments of a JWE). The protected header is a JSON object, so
# its base64url form starts with "ey" ('{"' or '{ ') or "ew" ('{' + newline/tab/CR). Requiring that
# prefix keeps dotted names such as "api.payments.internal" from matching.
_COMPACT_JWS: Final = re.compile(
    r"(?<![A-Za-z0-9_-])e[wy][A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*"
)

# Tool names that would advertise a credential capability to the model (agent-profile-03 §3.7).
_CREDENTIAL_NAME: Final = re.compile(
    r"token[_-]?exchange|exchange[_-]?token|replace(ment)?[_-]?token|txn[_-]?token"
    r"|access[_-]?token|credential|secret",
    re.IGNORECASE,
)

_CREDENTIAL_TYPES: Final = (VerifiedToken, SecretToken, TransactionClaims)
_SAFE_SCALARS: Final = (bool, int, float, Decimal, UUID, datetime, date, time)
_MAX_RESULT_DEPTH: Final = 64


@dataclass(frozen=True, slots=True)
class ToolInvocation:
    """What the token provider is told about a pending tool call.

    Deliberately excludes the tool arguments: model output must not flow into token-exchange
    requests (agent-profile-03 §3.7).
    """

    tool: str
    resource: str
    scope: Scope


type TokenProvider = Callable[[ToolInvocation], VerifiedToken | Awaitable[VerifiedToken]]
"""Returns the verified Txn-Token to use for a call, obtaining a replacement if needed.

Sync tools need a provider that returns a token directly; async tools accept either form.
"""


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """A tool description for the model: name, description and JSON Schema of its arguments."""

    name: str
    description: str
    parameters: Mapping[str, object]


class ResultMode(StrEnum):
    """What to do when a tool result contains something shaped like a token."""

    RAISE = "raise"
    REDACT = "redact"


class ToolArgumentError(PyTraTError):
    """Arguments supplied for a tool call failed validation."""

    http_status: ClassVar[int] = 400

    def __init__(self, detail: str) -> None:
        super().__init__(ReasonCode.TOOL_ARGUMENTS_INVALID, detail)


class ToolResultBlockedError(PyTraTError):
    """A tool result contained credential-shaped data or an unscannable value."""

    http_status: ClassVar[int] = 500

    def __init__(self, detail: str) -> None:
        super().__init__(ReasonCode.TOOL_RESULT_BLOCKED, detail)


@dataclass(frozen=True, slots=True)
class _Tool:
    name: str
    description: str
    scope: Scope
    resource: str
    requirements: AgentRequirements
    arguments: type[BaseModel]
    signature: inspect.Signature
    wrapper: Callable[..., object]


class ToolRuntime:
    """Runs LLM-requested tool calls under Transaction Token authorization.

    Not an isolation boundary on its own; see the module documentation.

    Example::

        runtime = ToolRuntime(agent=record, token_provider=provider, store=store, audit=sink)

        @runtime.protected_tool(scope="billing.read", resource="billing-api")
        def get_invoice(invoice_id: str) -> dict[str, str]:
            '''Fetch one invoice.'''
            ...
    """

    def __init__(
        self,
        *,
        agent: AgentRecord,
        token_provider: TokenProvider,
        store: AgentAttributeStore,
        audit: AuditSink,
        requirements: AgentRequirements | None = None,
        ordering: AssuranceOrdering | None = None,
        require_replacement: bool = True,
        result_mode: ResultMode = ResultMode.RAISE,
        service: str = "pytrat.agents.runtime",
    ) -> None:
        """Configure the runtime.

        Args:
            agent: This agent's record, from the trusted store.
            token_provider: Supplies the verified token for each call (see :data:`TokenProvider`).
            store: Trusted Agent Attribute Store, for ``require_verified_agent``.
            audit: Receives one granted or denied event per call.
            requirements: Default agent-chain requirements; tools may tighten them.
            ordering: Assurance ordering (default levels if omitted).
            require_replacement: The token must name this agent as ``proximate_agent``, i.e. the
                agent obtained a replacement before acting (agent-profile-03 §3.3, §5.14).
            result_mode: Raise (default) or redact when a result contains a token-shaped string.
            service: Service name recorded in audit events.
        """
        self._agent = agent
        self._provider = token_provider
        self._store = store
        self._audit = audit
        self._requirements = requirements or AgentRequirements()
        self._ordering = ordering or AssuranceOrdering()
        self._require_replacement = require_replacement
        self._result_mode = result_mode
        self._service = service
        self._tools: dict[str, _Tool] = {}

    # ------------------------------------------------------------ registration

    def protected_tool[**P, R](
        self,
        *,
        scope: str,
        resource: str,
        require_verified_agent: bool | None = None,
        minimum_assurance: str | None = None,
        name: str | None = None,
        description: str | None = None,
    ) -> Callable[[Callable[P, R]], Callable[P, R]]:
        """Register a sync or async function as a tool the model may call.

        Before each call the wrapper obtains the token, checks that every token in ``scope`` is
        in the token's scope (``SCOPE_INSUFFICIENT``), enforces the agent requirements, and
        validates the arguments strictly against the function's annotations. The function never
        receives the token. Its result is scanned for token-shaped strings.

        Args:
            scope: Space-delimited scope the call needs.
            resource: Logical downstream resource, passed to the token provider.
            require_verified_agent: Overrides the runtime default when not ``None``.
            minimum_assurance: Overrides the runtime default when not ``None``.
            name: Tool name shown to the model (default: the function name).
            description: Tool description (default: the function docstring's first paragraph).

        Raises:
            ConfigurationError: At decoration time, for a duplicate or credential-like name, an
                unannotated, variadic or credential-typed parameter, or an unknown assurance
                level.
        """
        required_scope = Scope.parse(scope)
        if minimum_assurance is not None:
            self._ordering.require_known(minimum_assurance)
        requirements = self._requirements
        if require_verified_agent is not None:
            requirements = replace(requirements, require_verified_agent=require_verified_agent)
        if minimum_assurance is not None:
            requirements = replace(requirements, minimum_assurance=minimum_assurance)

        def decorate(func: Callable[P, R]) -> Callable[P, R]:
            tool_name = func.__name__ if name is None else name
            self._check_name(tool_name)
            signature = inspect.signature(func)
            tool = _Tool(
                name=tool_name,
                description=description or _first_paragraph(func.__doc__) or tool_name,
                scope=required_scope,
                resource=resource,
                requirements=requirements,
                arguments=_arguments_model(tool_name, func, signature),
                signature=signature,
                wrapper=func,
            )
            if inspect.iscoroutinefunction(func):
                wrapped = cast("Callable[P, R]", self._wrap_async(tool, func))
            else:
                wrapped = self._wrap_sync(tool, func)
            self._tools[tool_name] = replace(tool, wrapper=wrapped)
            return wrapped

        return decorate

    def tool_specs(self) -> tuple[ToolSpec, ...]:
        """Describe the registered tools for the model, sorted by name.

        Only tools registered through :meth:`protected_tool` appear. The runtime never adds a
        token-exchange, replacement or credential tool (agent-profile-03 §3.7).
        """
        return tuple(
            ToolSpec(
                name=tool.name,
                description=tool.description,
                parameters=tool.arguments.model_json_schema(),
            )
            for tool in sorted(self._tools.values(), key=lambda tool: tool.name)
        )

    def call(self, name: str, arguments: Mapping[str, object]) -> object:
        """Dispatch a model-requested call to a sync tool by name.

        Raises:
            ToolArgumentError: If no tool has that name or the tool is async.
            PyTraTError: Anything the tool wrapper raises.
        """
        tool = self._lookup(name)
        if inspect.iscoroutinefunction(tool.wrapper):
            raise ToolArgumentError(f"tool '{name}' is async; use acall")
        return tool.wrapper(**arguments)

    async def acall(self, name: str, arguments: Mapping[str, object]) -> object:
        """Dispatch a model-requested call to a sync or async tool by name.

        Raises:
            ToolArgumentError: If no tool has that name.
            PyTraTError: Anything the tool wrapper raises.
        """
        tool = self._lookup(name)
        result = tool.wrapper(**arguments)
        if inspect.isawaitable(result):
            return await result
        return result

    # ------------------------------------------------------------ shells

    def _wrap_sync[**P, R](self, tool: _Tool, func: Callable[P, R]) -> Callable[P, R]:
        plain_func = cast("Callable[..., object]", func)

        @functools.wraps(func)
        def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            invocation = self._invocation(tool)
            token = self._obtain_sync(tool, invocation)
            validated = self._admit(tool, token, args, kwargs)
            return cast("R", self._release(tool, token, plain_func(**validated)))

        return sync_wrapper

    def _wrap_async(
        self, tool: _Tool, func: Callable[..., Awaitable[object]]
    ) -> Callable[..., Awaitable[object]]:
        @functools.wraps(func)
        async def async_wrapper(*args: object, **kwargs: object) -> object:
            invocation = self._invocation(tool)
            token = await self._obtain_async(tool, invocation)
            validated = self._admit(tool, token, args, kwargs)
            return self._release(tool, token, await func(**validated))

        return async_wrapper

    def _obtain_sync(self, tool: _Tool, invocation: ToolInvocation) -> VerifiedToken:
        result = self._call_provider(tool, invocation)
        if inspect.isawaitable(result):
            if inspect.iscoroutine(result):
                result.close()
            error = ConfigurationError("sync tool requires a synchronous token provider")
            self._deny(tool, None, error)
            raise error
        return result

    async def _obtain_async(self, tool: _Tool, invocation: ToolInvocation) -> VerifiedToken:
        result = self._call_provider(tool, invocation)
        if not inspect.isawaitable(result):
            return result
        try:
            return await result
        except PyTraTError as exc:
            self._deny(tool, None, exc)
            raise
        except Exception as exc:
            error = DependencyError("token provider failed")
            self._deny(tool, None, error)
            raise error from exc

    def _call_provider(
        self, tool: _Tool, invocation: ToolInvocation
    ) -> VerifiedToken | Awaitable[VerifiedToken]:
        try:
            return self._provider(invocation)
        except PyTraTError as exc:
            self._deny(tool, None, exc)
            raise
        except Exception as exc:
            # Fail closed: no token means no call.
            error = DependencyError("token provider failed")
            self._deny(tool, None, error)
            raise error from exc

    # ------------------------------------------------------------ pure-ish core

    def _invocation(self, tool: _Tool) -> ToolInvocation:
        return ToolInvocation(tool=tool.name, resource=tool.resource, scope=tool.scope)

    def _admit(
        self,
        tool: _Tool,
        token: VerifiedToken,
        args: tuple[object, ...],
        kwargs: Mapping[str, object],
    ) -> dict[str, object]:
        """Authorize, then validate arguments. Emits the granted/denied audit event."""
        try:
            self._authorize(tool, token.claims)
            validated = _validate_arguments(tool, args, kwargs)
        except PyTraTError as exc:
            self._deny(tool, token, exc)
            raise
        self._emit(EventType.AUTHORIZATION_GRANTED, tool, token, None)
        return validated

    def _authorize(self, tool: _Tool, claims: TransactionClaims) -> None:
        if not tool.scope.issubset(claims.scope):
            raise AuthorizationError(
                ReasonCode.SCOPE_INSUFFICIENT, "token scope does not cover this tool"
            )
        if self._require_replacement:
            ctx = claims.agentic_ctx
            # agent-profile-03 §3.3: an agent MUST replace before acting when chain integrity
            # is enforced, so the token must name this agent as the proximate agent.
            if ctx is None or ctx.proximate_agent.id != self._agent.id:
                raise AuthorizationError(
                    ReasonCode.AGENT_CONTEXT_MISSING,
                    "token does not name this agent as proximate agent; replacement required",
                )
        check_agent_requirements(claims, tool.requirements, self._ordering, self._store)

    def _release(self, tool: _Tool, token: VerifiedToken, result: object) -> object:
        try:
            return _guard(result, self._result_mode, token.forwardable.reveal(), depth=0)
        except ToolResultBlockedError as exc:
            self._deny(tool, token, exc)
            raise

    def _deny(self, tool: _Tool, token: VerifiedToken | None, error: PyTraTError) -> None:
        self._emit(EventType.AUTHORIZATION_DENIED, tool, token, error.reason)

    def _emit(
        self,
        event_type: EventType,
        tool: _Tool,
        token: VerifiedToken | None,
        reason: ReasonCode | None,
    ) -> None:
        self._audit.emit(
            AuditEvent.for_claims(
                event_type,
                service=self._service,
                claims=token.claims if token is not None else None,
                token_digest=token.digest if token is not None else None,
                reason_code=reason,
                caller_workload=self._agent.id,
                detail=MappingProxyType({"tool": tool.name, "resource": tool.resource}),
            )
        )

    def _lookup(self, name: str) -> _Tool:
        tool = self._tools.get(name)
        if tool is None:
            raise ToolArgumentError("unknown tool")
        return tool

    def _check_name(self, tool_name: str) -> None:
        if not tool_name:
            raise ConfigurationError("tool name must be non-empty")
        if tool_name in self._tools:
            raise ConfigurationError(f"duplicate tool name {tool_name!r}")
        if _CREDENTIAL_NAME.search(tool_name):
            # agent-profile-03 §3.7: credential operations MUST NOT be exposed as tools.
            raise ConfigurationError(f"tool name {tool_name!r} suggests a credential operation")


# ---------------------------------------------------------------- arguments


def _arguments_model(
    tool_name: str, func: Callable[..., object], signature: inspect.Signature
) -> type[BaseModel]:
    try:
        hints = get_type_hints(func)
    except (NameError, TypeError) as exc:
        raise ConfigurationError(f"tool {tool_name!r} has unresolvable annotations") from exc
    fields: dict[str, tuple[object, object]] = {}
    for parameter in signature.parameters.values():
        if parameter.kind in (parameter.VAR_POSITIONAL, parameter.VAR_KEYWORD):
            raise ConfigurationError(f"tool {tool_name!r} must not take *args or **kwargs")
        annotation = hints.get(parameter.name)
        if annotation is None:
            raise ConfigurationError(f"tool {tool_name!r} parameter must be annotated")
        if _is_credential_type(annotation):
            raise ConfigurationError(f"tool {tool_name!r} must not accept credentials")
        default = ... if parameter.default is parameter.empty else parameter.default
        fields[parameter.name] = (annotation, default)
    config = ConfigDict(strict=True, extra="forbid", hide_input_in_errors=True, frozen=True)
    try:
        model: type[BaseModel] = create_model(  # type: ignore[call-overload]  # dynamic fields
            f"{tool_name}_arguments", __config__=config, **fields
        )
        model.model_json_schema()  # fail at registration, not when the model asks for specs
    except (PydanticUserError, NameError, TypeError, ValueError) as exc:
        raise ConfigurationError(f"tool {tool_name!r} has unsupported parameters") from exc
    return model


def _is_credential_type(annotation: object) -> bool:
    if isinstance(annotation, type) and issubclass(annotation, _CREDENTIAL_TYPES):
        return True
    return any(_is_credential_type(arg) for arg in getattr(annotation, "__args__", ()))


def _validate_arguments(
    tool: _Tool, args: tuple[object, ...], kwargs: Mapping[str, object]
) -> dict[str, object]:
    try:
        bound = tool.signature.bind(*args, **kwargs)
    except TypeError:
        raise ToolArgumentError(f"arguments for tool '{tool.name}' do not match") from None
    try:
        model = tool.arguments.model_validate(dict(bound.arguments))
    except ValidationError as exc:
        first = exc.errors(include_input=False, include_url=False)[0]
        where = ".".join(str(part) for part in first["loc"]) or "arguments"
        raise ToolArgumentError(f"tool argument '{where}' is invalid") from None
    return {field_name: getattr(model, field_name) for field_name in type(model).model_fields}


def _first_paragraph(doc: str | None) -> str:
    if not doc:
        return ""
    return inspect.cleandoc(doc).split("\n\n", 1)[0].replace("\n", " ").strip()


# ---------------------------------------------------------------- result guard


def find_token_like(text: str) -> bool:
    """Return True if ``text`` contains a substring shaped like a compact JWS."""
    return _COMPACT_JWS.search(text) is not None


def _guard(value: object, mode: ResultMode, secret: str, *, depth: int) -> object:
    """Scan ``value`` recursively; raise or redact token-shaped strings.

    Fail closed: values of types that cannot be scanned are blocked.
    """
    if depth > _MAX_RESULT_DEPTH:
        raise ToolResultBlockedError("tool result is nested too deeply to scan")
    if value is None or isinstance(value, _SAFE_SCALARS):
        return value
    if isinstance(value, str):
        return _guard_text(value, mode, secret)
    if isinstance(value, bytes | bytearray):
        text = bytes(value).decode("latin-1")
        guarded = _guard_text(text, mode, secret)
        return value if guarded is text else guarded.encode("latin-1")
    return _guard_container(value, mode, secret, depth=depth + 1)


def _guard_container(value: object, mode: ResultMode, secret: str, *, depth: int) -> object:
    if isinstance(value, BaseModel):
        return _guard(value.model_dump(mode="python"), mode, secret, depth=depth)
    if isinstance(value, Mapping):
        return {
            _guard(key, mode, secret, depth=depth): _guard(item, mode, secret, depth=depth)
            for key, item in value.items()
        }
    if isinstance(value, list | tuple):
        items = [_guard(item, mode, secret, depth=depth) for item in value]
        return items if isinstance(value, list) else tuple(items)
    if isinstance(value, set | frozenset):
        return frozenset(_guard(item, mode, secret, depth=depth) for item in value)
    raise ToolResultBlockedError("tool result contains a value of an unscannable type")


def _guard_text(text: str, mode: ResultMode, secret: str) -> str:
    leaked = bool(secret) and secret in text
    leaked = leaked or find_token_like(text)
    if not leaked:
        return text
    # agent-profile-03 §3.7: credentials MUST NOT appear in the LLM's context window.
    if mode is ResultMode.RAISE:
        raise ToolResultBlockedError("tool result contains a token-shaped value")
    redacted = text.replace(secret, REDACTED) if secret else text
    return _COMPACT_JWS.sub(REDACTED, redacted)
