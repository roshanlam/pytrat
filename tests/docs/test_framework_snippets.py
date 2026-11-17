"""The Django and agents guides' snippets behave as documented."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from pytrat.agents import ToolArgumentError
from pytrat.cli import app as cli
from pytrat.core import MemorySink, PyTraTError, ReasonCode
from pytrat.core.testing import TokenFactory
from pytrat.django import parse_settings
from pytrat.django.decorators import guard_of, is_exempt
from pytrat.policy import TransactionEnforcer

AGENT_CTX = {
    "originator": {"id": "report-agent"},
    "proximate_agent": {"id": "report-agent"},
    "chain_metadata": {"hop_count": 1, "min_assurance_level": "high"},
}


def test_django_settings_parse(snippet) -> None:
    module = snippet("django_app")
    settings = parse_settings(module.PYTRAT)
    assert settings.protected_prefixes == ("/internal/",)
    assert "pytrat.django" in module.INSTALLED_APPS


def test_django_enforcer_factory_loads_cli_keys(snippet, tmp_path: Path) -> None:
    for kid in ("tts", "payment-service"):
        result = CliRunner().invoke(cli, ["keys", "generate", "--kid", kid, "--out", str(tmp_path)])
        assert result.exit_code == 0, result.output
    enforcer = snippet("django_app").build_enforcer(tmp_path)
    assert isinstance(enforcer, TransactionEnforcer)
    assert enforcer.service == "ledger-service"


def test_django_views_carry_their_guards(snippet) -> None:
    module = snippet("django_app")
    inline = guard_of(module.record_entry)
    assert inline is not None
    assert inline.policy is not None
    assert inline.policy.binding.fields == (
        "source_account",
        "destination_account",
        "amount_minor",
        "currency",
    )
    by_name = guard_of(module.account)
    assert by_name is not None
    assert by_name.policy_id == "account-read"
    assert is_exempt(module.healthz)


@pytest.fixture
def factory() -> TokenFactory:
    return TokenFactory.create("ES256")


def test_agent_runtime_runs_an_authorized_tool(snippet, factory: TokenFactory) -> None:
    verified = factory.verifier().verify(factory.mint(scope="reports.read", agentic_ctx=AGENT_CTX))
    sink = MemorySink()
    runtime = snippet("agent_runtime").build_runtime(lambda _: verified, sink)

    assert [spec.name for spec in runtime.tool_specs()] == ["get_report"]
    assert runtime.call("get_report", {"report_id": "r-1", "quarter": 3}) == {
        "report_id": "r-1",
        "quarter": "Q3",
        "status": "final",
    }
    with pytest.raises(ToolArgumentError):
        runtime.call("get_report", {"report_id": "r-1", "quarter": "3"})


def test_agent_store_example_loads() -> None:
    from pytrat.agents import YamlAgentStore

    from .conftest import SNIPPETS

    store = YamlAgentStore(SNIPPETS / "agents.yaml")
    research = store.by_client_id("research-agent-client")
    assert research is not None
    assert research.assurance_level == "low"
    assert store.is_registered("report-agent")


def test_agent_runtime_denies_wrong_scope(snippet, factory: TokenFactory) -> None:
    verified = factory.verifier().verify(factory.mint(agentic_ctx=AGENT_CTX))
    runtime = snippet("agent_runtime").build_runtime(lambda _: verified, MemorySink())
    with pytest.raises(PyTraTError) as denied:
        runtime.call("get_report", {"report_id": "r-1", "quarter": 3})
    assert denied.value.reason is ReasonCode.SCOPE_INSUFFICIENT


TCTX = {
    "source_account": "account-A",
    "destination_account": "DE89370400440532013000",
    "amount_minor": 10000,
    "currency": "USD",
}


def test_binding_snippet_matches_the_concepts_table(snippet) -> None:
    binding = snippet("binding")
    request = {"amount_minor": 10000, "currency": "USD", "iban": "de89 3704 0044 0532 0130 00"}
    result = binding.TRANSFER.check(TCTX, request)
    assert result.transforms == ("iban-normalisation",)
    binding.ACCOUNT.check(TCTX, {"account_id": "account-A"})

    for bad in [
        {**request, "amount_minor": "10000"},
        {**request, "amount_minor": True},
        {**request, "amount_minor": 100.0},
        {**request, "iban": 42},
        {"currency": "USD", "iban": request["iban"]},
    ]:
        with pytest.raises(PyTraTError) as denied:
            binding.TRANSFER.check(TCTX, bad)
        assert denied.value.reason is ReasonCode.TRANSACTION_CONTEXT_MISMATCH
    with pytest.raises(PyTraTError) as missing:
        binding.TRANSFER.check({"currency": "USD"}, request)
    assert missing.value.reason is ReasonCode.TRANSACTION_CONTEXT_MISSING
