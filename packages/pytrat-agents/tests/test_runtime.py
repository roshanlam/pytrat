from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Callable
from decimal import Decimal
from typing import Any

import pytest
from pydantic import BaseModel

from pytrat.agents import (
    REDACTED,
    AgentRecord,
    AgentRequirements,
    InMemoryAgentStore,
    ResultMode,
    ToolArgumentError,
    ToolInvocation,
    ToolResultBlockedError,
    ToolRuntime,
    find_token_like,
)
from pytrat.agents import runtime as runtime_module
from pytrat.core import (
    AuthorizationError,
    ConfigurationError,
    DependencyError,
    EventType,
    MemorySink,
    ReasonCode,
    Scope,
    SecretToken,
    TokenError,
    TransactionClaims,
    VerifiedToken,
)

type Mint = Callable[..., VerifiedToken]

SAMPLE_JWS = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJlLWJ5dGVz"


@pytest.fixture
def sink() -> MemorySink:
    return MemorySink()


@pytest.fixture
def invocations() -> list[ToolInvocation]:
    return []


@pytest.fixture
def make_runtime(
    mint_verified: Mint,
    store: InMemoryAgentStore,
    internal: AgentRecord,
    sink: MemorySink,
    invocations: list[ToolInvocation],
) -> Callable[..., ToolRuntime]:
    def make(
        token: VerifiedToken | None = None,
        *,
        provider: Any = None,
        agent: AgentRecord = internal,
        **kwargs: Any,
    ) -> ToolRuntime:
        verified = token or mint_verified()

        def default_provider(invocation: ToolInvocation) -> VerifiedToken:
            invocations.append(invocation)
            return verified

        return ToolRuntime(
            agent=agent,
            token_provider=provider or default_provider,
            store=store,
            audit=sink,
            **kwargs,
        )

    return make


def test_granted_call_runs_tool_and_audits(
    make_runtime: Callable[..., ToolRuntime],
    sink: MemorySink,
    invocations: list[ToolInvocation],
) -> None:
    runtime = make_runtime()
    received: list[dict[str, object]] = []

    @runtime.protected_tool(scope="billing.read", resource="billing-api")
    def get_invoice(invoice_id: str, include_lines: bool = False) -> dict[str, object]:
        """Fetch one invoice.

        Longer description that is not shown.
        """
        received.append({"invoice_id": invoice_id, "include_lines": include_lines})
        return {"id": invoice_id, "total": 10}

    assert get_invoice(invoice_id="inv-1") == {"id": "inv-1", "total": 10}
    assert runtime.call("get_invoice", {"invoice_id": "inv-2", "include_lines": True}) == {
        "id": "inv-2",
        "total": 10,
    }
    assert received[1] == {"invoice_id": "inv-2", "include_lines": True}
    assert invocations[0] == ToolInvocation(
        tool="get_invoice", resource="billing-api", scope=Scope.of("billing.read")
    )
    granted = sink.of_type(EventType.AUTHORIZATION_GRANTED)
    assert len(granted) == 2
    assert granted[0].detail == {"tool": "get_invoice", "resource": "billing-api"}
    assert granted[0].token_digest is not None
    assert granted[0].caller_workload == "1p-billing-svc-v2"


def test_tool_never_receives_the_token(make_runtime: Callable[..., ToolRuntime]) -> None:
    runtime = make_runtime()
    seen: list[tuple[object, ...]] = []

    @runtime.protected_tool(scope="billing.read", resource="r")
    def echo(value: str) -> str:
        seen.append((value,))
        return value

    echo("x")
    assert seen == [("x",)]

    def takes_token(token: VerifiedToken) -> str:
        return ""

    def takes_secret(value: SecretToken | None) -> str:
        return ""

    def takes_claims(claims: list[TransactionClaims]) -> str:
        return ""

    for func in (takes_token, takes_secret, takes_claims):
        with pytest.raises(ConfigurationError):
            runtime.protected_tool(scope="billing.read", resource="r")(func)


def test_scope_insufficient(make_runtime: Callable[..., ToolRuntime], sink: MemorySink) -> None:
    runtime = make_runtime()

    @runtime.protected_tool(scope="billing.write", resource="r")
    def pay(amount: int) -> int:
        return amount

    with pytest.raises(AuthorizationError) as excinfo:
        pay(amount=1)
    assert excinfo.value.reason is ReasonCode.SCOPE_INSUFFICIENT
    denied = sink.of_type(EventType.AUTHORIZATION_DENIED)
    assert denied[0].reason_code is ReasonCode.SCOPE_INSUFFICIENT


@pytest.mark.parametrize("proximate", ["someone-else", None])
def test_token_must_name_this_agent_as_proximate(
    make_runtime: Callable[..., ToolRuntime],
    mint_verified: Mint,
    ctx_payload: Callable[..., dict[str, object]],
    proximate: str | None,
) -> None:
    """agent-profile-03 §3.3: agents MUST replace before downstream invocation."""
    ctx = None if proximate is None else ctx_payload(proximate=proximate)
    token = mint_verified(agentic_ctx=ctx) if ctx else mint_verified(agentic_ctx=None)
    runtime = make_runtime(token)

    @runtime.protected_tool(scope="billing.read", resource="r")
    def read() -> str:
        return "ok"

    with pytest.raises(AuthorizationError) as excinfo:
        read()
    assert excinfo.value.reason is ReasonCode.AGENT_CONTEXT_MISSING

    lenient = make_runtime(token, require_replacement=False)

    @lenient.protected_tool(scope="billing.read", resource="r")
    def read_again() -> str:
        return "ok"

    assert read_again() == "ok"


def test_per_tool_minimum_assurance(
    make_runtime: Callable[..., ToolRuntime],
    mint_verified: Mint,
    ctx_payload: Callable[..., dict[str, object]],
) -> None:
    token = mint_verified(agentic_ctx=ctx_payload(proximate="1p-billing-svc-v2", hop_count=2))
    runtime = make_runtime(token, requirements=AgentRequirements(minimum_assurance="unverified"))

    @runtime.protected_tool(scope="billing.read", resource="r")
    def low_risk() -> str:
        return "ok"

    @runtime.protected_tool(scope="billing.read", resource="r", minimum_assurance="high")
    def high_risk() -> str:
        return "ok"

    assert low_risk() == "ok"
    with pytest.raises(AuthorizationError) as excinfo:
        high_risk()
    assert excinfo.value.reason is ReasonCode.AGENT_ASSURANCE_INSUFFICIENT
    with pytest.raises(ConfigurationError):
        runtime.protected_tool(scope="a", resource="r", minimum_assurance="ultra")


def test_per_tool_verified_agent(
    make_runtime: Callable[..., ToolRuntime],
    mint_verified: Mint,
    ctx_payload: Callable[..., dict[str, object]],
) -> None:
    ghost = AgentRecord(
        id="ghost", name="g", owner="o", assurance_level="high", version="1", provenance="p"
    )
    token = mint_verified(agentic_ctx=ctx_payload(proximate="ghost", hop_count=2))
    runtime = make_runtime(token, agent=ghost)

    @runtime.protected_tool(scope="billing.read", resource="r")
    def unchecked() -> str:
        return "ok"

    @runtime.protected_tool(scope="billing.read", resource="r", require_verified_agent=True)
    def checked() -> str:
        return "ok"

    assert unchecked() == "ok"
    with pytest.raises(AuthorizationError) as excinfo:
        checked()
    assert excinfo.value.reason is ReasonCode.AGENT_UNVERIFIED


def test_argument_validation(make_runtime: Callable[..., ToolRuntime], sink: MemorySink) -> None:
    runtime = make_runtime()

    @runtime.protected_tool(scope="billing.read", resource="r")
    def lookup(invoice_id: str, limit: int = 10) -> list[object]:
        return [invoice_id, limit]

    assert lookup("a", 2) == ["a", 2]
    assert runtime.call("lookup", {"invoice_id": "a"}) == ["a", 10]
    bad_calls: list[dict[str, object]] = [
        {"invoice_id": 5},  # wrong type
        {"invoice_id": "a", "limit": "5"},  # strict: no coercion
        {},  # missing
        {"invoice_id": "a", "admin": True},  # unknown argument
    ]
    for arguments in bad_calls:
        with pytest.raises(ToolArgumentError) as excinfo:
            runtime.call("lookup", arguments)
        assert excinfo.value.reason is ReasonCode.TOOL_ARGUMENTS_INVALID
        assert excinfo.value.http_status == 400
    with pytest.raises(ToolArgumentError):
        lookup("a", 1, 2)  # type: ignore[call-arg]
    assert (
        sink.of_type(EventType.AUTHORIZATION_DENIED)[0].reason_code
        is ReasonCode.TOOL_ARGUMENTS_INVALID
    )


def test_registration_rejects_unsafe_signatures(make_runtime: Callable[..., ToolRuntime]) -> None:
    runtime = make_runtime()
    decorate = runtime.protected_tool(scope="billing.read", resource="r")

    def variadic(*values: str) -> str:
        return ""

    def keywords(**values: str) -> str:
        return ""

    def unannotated(value) -> str:  # type: ignore[no-untyped-def]
        return ""

    def unresolvable(value: DoesNotExist) -> str:  # type: ignore[name-defined]  # noqa: F821
        return ""

    def bad_type(value: object) -> str:
        return ""

    bad_type.__annotations__["value"] = 42  # not a type pydantic can build a schema for

    for func in (variadic, keywords, unannotated, unresolvable, bad_type):
        with pytest.raises(ConfigurationError):
            decorate(func)


def test_registration_rejects_duplicate_and_empty_names(
    make_runtime: Callable[..., ToolRuntime],
) -> None:
    runtime = make_runtime()

    @runtime.protected_tool(scope="billing.read", resource="r")
    def tool() -> str:
        return ""

    with pytest.raises(ConfigurationError):
        runtime.protected_tool(scope="billing.read", resource="r", name="tool")(tool)
    with pytest.raises(ConfigurationError):
        runtime.protected_tool(scope="billing.read", resource="r", name="")(tool)


@pytest.mark.parametrize(
    "name",
    [
        "token_exchange",
        "exchange_token",
        "replace_token",
        "get_txn_token",
        "read_secret",
        "load_credentials",
        "fetch_access_token",
        "request_replacement_token",
    ],
)
def test_credential_like_tool_names_are_rejected(
    make_runtime: Callable[..., ToolRuntime], name: str
) -> None:
    """agent-profile-03 §3.7: token exchange MUST NOT be exposed as a tool."""
    runtime = make_runtime()

    def func() -> str:
        return ""

    with pytest.raises(ConfigurationError):
        runtime.protected_tool(scope="billing.read", resource="r", name=name)(func)


def test_unknown_tool(make_runtime: Callable[..., ToolRuntime]) -> None:
    runtime = make_runtime()
    with pytest.raises(ToolArgumentError):
        runtime.call("nope", {})


async def test_async_tool_with_sync_and_async_providers(
    make_runtime: Callable[..., ToolRuntime], mint_verified: Mint, sink: MemorySink
) -> None:
    token = mint_verified()

    async def async_provider(invocation: ToolInvocation) -> VerifiedToken:
        return token

    for runtime in (make_runtime(token), make_runtime(provider=async_provider)):

        @runtime.protected_tool(scope="billing.read", resource="r", description="Adds one.")
        async def add_one(value: int) -> int:
            return value + 1

        assert await add_one(value=1) == 2
        assert await runtime.acall("add_one", {"value": 2}) == 3
        with pytest.raises(ToolArgumentError):
            runtime.call("add_one", {"value": 1})


async def test_acall_dispatches_sync_tools(make_runtime: Callable[..., ToolRuntime]) -> None:
    runtime = make_runtime()

    @runtime.protected_tool(scope="billing.read", resource="r")
    def sync_tool() -> str:
        return "sync"

    assert await runtime.acall("sync_tool", {}) == "sync"


def test_sync_tool_rejects_async_provider(
    make_runtime: Callable[..., ToolRuntime], mint_verified: Mint, sink: MemorySink
) -> None:
    token = mint_verified()

    async def async_provider(invocation: ToolInvocation) -> VerifiedToken:
        return token

    runtime = make_runtime(provider=async_provider)

    @runtime.protected_tool(scope="billing.read", resource="r")
    def sync_tool() -> str:
        return "sync"

    with pytest.raises(ConfigurationError):
        sync_tool()
    assert sink.of_type(EventType.AUTHORIZATION_DENIED)


class _Awaitable:
    def __init__(self, token: VerifiedToken) -> None:
        self.token = token

    def __await__(self):  # type: ignore[no-untyped-def]
        yield from ()
        return self.token


def test_sync_tool_rejects_non_coroutine_awaitable(
    make_runtime: Callable[..., ToolRuntime], mint_verified: Mint
) -> None:
    token = mint_verified()
    runtime = make_runtime(provider=lambda invocation: _Awaitable(token))

    @runtime.protected_tool(scope="billing.read", resource="r")
    def sync_tool() -> str:
        return "sync"

    with pytest.raises(ConfigurationError):
        sync_tool()


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (TokenError(ReasonCode.TOKEN_EXPIRED, "expired"), TokenError),
        (RuntimeError("tts down"), DependencyError),
    ],
)
async def test_provider_failure_fails_closed(
    make_runtime: Callable[..., ToolRuntime],
    sink: MemorySink,
    error: Exception,
    expected: type[Exception],
) -> None:
    def failing(invocation: ToolInvocation) -> VerifiedToken:
        raise error

    async def failing_async(invocation: ToolInvocation) -> VerifiedToken:
        raise error

    called: list[str] = []
    for provider in (failing, failing_async):
        runtime = make_runtime(provider=provider)

        @runtime.protected_tool(scope="billing.read", resource="r")
        async def tool() -> str:
            called.append("x")
            return "x"

        with pytest.raises(expected):
            await tool()
    sync_runtime = make_runtime(provider=failing)

    @sync_runtime.protected_tool(scope="billing.read", resource="r")
    def sync_tool() -> str:
        called.append("x")
        return "x"

    with pytest.raises(expected):
        sync_tool()
    assert called == []
    assert len(sink.of_type(EventType.AUTHORIZATION_DENIED)) == 3


class _Report(BaseModel):
    note: str


@pytest.mark.parametrize(
    "result",
    [
        SAMPLE_JWS,
        f"prefix {SAMPLE_JWS} suffix",
        {"nested": [{"deep": (SAMPLE_JWS,)}]},
        {SAMPLE_JWS: "as a key"},
        frozenset({SAMPLE_JWS}),
        SAMPLE_JWS.encode(),
        bytearray(SAMPLE_JWS.encode()),
        _Report(note=SAMPLE_JWS),
        "eyJ0eXAiOiJ0eG50b2tlbitqd3QifQ.eyJ0eG4iOiIxIn0.",  # unsigned shape
    ],
)
def test_result_guard_blocks_token_shapes(
    make_runtime: Callable[..., ToolRuntime], sink: MemorySink, result: object
) -> None:
    """agent-profile-03 §3.7: credentials MUST NOT appear in the LLM's context window."""
    runtime = make_runtime()

    @runtime.protected_tool(scope="billing.read", resource="r")
    def leaky() -> object:
        return result

    with pytest.raises(ToolResultBlockedError) as excinfo:
        leaky()
    assert excinfo.value.reason is ReasonCode.TOOL_RESULT_BLOCKED
    assert sink.of_type(EventType.AUTHORIZATION_DENIED)[-1].reason_code is (
        ReasonCode.TOOL_RESULT_BLOCKED
    )


def test_result_guard_redact_mode(make_runtime: Callable[..., ToolRuntime]) -> None:
    runtime = make_runtime(result_mode=ResultMode.REDACT)

    @runtime.protected_tool(scope="billing.read", resource="r")
    def leaky() -> object:
        return {
            "text": f"token={SAMPLE_JWS};",
            "list": [SAMPLE_JWS, "safe"],
            "raw": SAMPLE_JWS.encode(),
            "set": {"safe"},
            "ok": b"plain",
        }

    assert leaky() == {
        "text": f"token={REDACTED};",
        "list": [REDACTED, "safe"],
        "raw": REDACTED.encode(),
        "set": frozenset({"safe"}),
        "ok": b"plain",
    }


def test_result_guard_redacts_the_exact_runtime_token(
    make_runtime: Callable[..., ToolRuntime], mint_verified: Mint
) -> None:
    token = mint_verified()
    runtime = make_runtime(token, result_mode=ResultMode.REDACT)
    raw = token.forwardable.reveal()

    @runtime.protected_tool(scope="billing.read", resource="r")
    def leaky() -> str:
        return f"<{raw}>"

    assert leaky() == f"<{REDACTED}>"


@pytest.mark.parametrize(
    "result",
    [
        "api.payments.internal",
        "version 1.2.3",
        "keyword.with.dots",
        {"when": dt.datetime(2026, 1, 1, tzinfo=dt.UTC), "d": dt.date(2026, 1, 1)},
        [Decimal("1.5"), uuid.UUID(int=1), 1.5, True, None, dt.time(1, 2)],
    ],
)
def test_result_guard_allows_benign_values(
    make_runtime: Callable[..., ToolRuntime], result: object
) -> None:
    runtime = make_runtime()

    @runtime.protected_tool(scope="billing.read", resource="r")
    def benign() -> object:
        return result

    assert benign() == result


def test_result_guard_blocks_unscannable_and_deep_values(
    make_runtime: Callable[..., ToolRuntime],
) -> None:
    runtime = make_runtime()
    deep: list[object] = []
    cursor = deep
    for _ in range(100):
        nxt: list[object] = []
        cursor.append(nxt)
        cursor = nxt

    def returning(value: object) -> Callable[[], object]:
        def odd() -> object:
            return value

        return odd

    for index, result in enumerate((object(), deep)):
        tool = runtime.protected_tool(scope="billing.read", resource="r", name=f"t{index}")(
            returning(result)
        )
        with pytest.raises(ToolResultBlockedError):
            tool()


def test_guard_text_without_secret() -> None:
    assert runtime_module._guard_text(SAMPLE_JWS, ResultMode.REDACT, "") == REDACTED


def test_find_token_like() -> None:
    assert find_token_like(SAMPLE_JWS)
    assert not find_token_like("a.b.c")
    assert not find_token_like("xeyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig")


def test_tool_specs(make_runtime: Callable[..., ToolRuntime]) -> None:
    runtime = make_runtime()

    @runtime.protected_tool(scope="billing.read", resource="r")
    def get_invoice(invoice_id: str, limit: int = 5) -> str:
        """Fetch one invoice.

        Details hidden from the model.
        """
        return invoice_id

    @runtime.protected_tool(scope="billing.read", resource="r", name="a_tool")
    def undocumented() -> str:
        return ""

    specs = runtime.tool_specs()
    assert [spec.name for spec in specs] == ["a_tool", "get_invoice"]
    assert specs[0].description == "a_tool"
    assert specs[1].description == "Fetch one invoice."
    parameters = specs[1].parameters
    assert parameters["required"] == ["invoice_id"]
    assert set(parameters["properties"]) == {"invoice_id", "limit"}  # type: ignore[call-overload]
