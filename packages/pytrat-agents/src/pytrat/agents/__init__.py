"""PyTraT agents: the AI-agent profile of Transaction Tokens (experimental).

Implements ``draft-araut-oauth-transaction-tokens-for-agents-03`` (see :data:`PROFILE_VERSION`) on
top of ``draft-ietf-oauth-transaction-tokens-11``. The agent draft is an individual submission and
not adopted by the OAuth WG; this package and its API may change with every draft revision.

Contents:

- :mod:`~pytrat.agents.registry`: the trusted Agent Attribute Store.
- :mod:`~pytrat.agents.identity`: agent identification at issuance.
- :mod:`~pytrat.agents.replacement`: pure ``agentic_ctx`` computation for the TTS.
- :mod:`~pytrat.agents.policy`: resource-side agent-chain requirements.
- :mod:`~pytrat.agents.runtime`: the trusted tool runtime for LLM agents. An in-process decorator
  is not an isolation boundary; see its documentation.
"""

from __future__ import annotations

from typing import Final

from pytrat.agents.assurance import DEFAULT_LEVELS, AssuranceOrdering
from pytrat.agents.identity import AgentMode, agent_mode, resolve_agent
from pytrat.agents.policy import AgentRequirements, check_agent_requirements
from pytrat.agents.registry import (
    SQLITE_SCHEMA,
    AgentAttributeStore,
    AgentRecord,
    InMemoryAgentStore,
    SqliteAgentStore,
    YamlAgentStore,
)
from pytrat.agents.replacement import (
    MAX_HOP_LIMIT,
    AgentLimits,
    AgentReplacementPlan,
    append_workload,
    assert_replacement_attenuates,
    initial_agentic_ctx,
    next_agentic_ctx,
    plan_agent_replacement,
    strip_for_egress,
)
from pytrat.agents.runtime import (
    REDACTED,
    ResultMode,
    TokenProvider,
    ToolArgumentError,
    ToolInvocation,
    ToolResultBlockedError,
    ToolRuntime,
    ToolSpec,
    find_token_like,
)
from pytrat.core.constants import SUPPORTED_DRAFTS

#: The agent-profile draft revision this package implements.
PROFILE_VERSION: Final = SUPPORTED_DRAFTS["agent-profile"]

__all__ = [
    "DEFAULT_LEVELS",
    "MAX_HOP_LIMIT",
    "PROFILE_VERSION",
    "REDACTED",
    "SQLITE_SCHEMA",
    "AgentAttributeStore",
    "AgentLimits",
    "AgentMode",
    "AgentRecord",
    "AgentReplacementPlan",
    "AgentRequirements",
    "AssuranceOrdering",
    "InMemoryAgentStore",
    "ResultMode",
    "SqliteAgentStore",
    "TokenProvider",
    "ToolArgumentError",
    "ToolInvocation",
    "ToolResultBlockedError",
    "ToolRuntime",
    "ToolSpec",
    "YamlAgentStore",
    "agent_mode",
    "append_workload",
    "assert_replacement_attenuates",
    "check_agent_requirements",
    "find_token_like",
    "initial_agentic_ctx",
    "next_agentic_ctx",
    "plan_agent_replacement",
    "resolve_agent",
    "strip_for_egress",
]
