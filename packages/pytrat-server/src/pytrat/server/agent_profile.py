"""Wiring of the experimental agent profile (agent-profile-03) into the TTS.

All agent *rules* live in :mod:`pytrat.agents`; this module only builds the deployment's store and
limits from configuration and identifies the requesting workload's agent record.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from pytrat.agents import AgentAttributeStore, AgentLimits, AgentRecord, YamlAgentStore
from pytrat.core.assurance import AssuranceOrdering

if TYPE_CHECKING:
    from pytrat.server.settings import AgentsConfig
    from pytrat.server.workloads import WorkloadIdentity

__all__ = ["AgentProfile"]


@dataclass(frozen=True, slots=True)
class AgentProfile:
    """The agent profile as configured for this TTS.

    Attributes:
        store: The trusted Agent Attribute Store (agent-profile-03 §3.6).
        limits: Hop limit and assurance ordering.
        include_assurance: Record ``min_assurance_level`` at initial issuance.
        attr_store_ref: Optional informational store URI (agent-profile-03 §3.5.1).
    """

    store: AgentAttributeStore
    limits: AgentLimits
    include_assurance: bool = True
    attr_store_ref: str | None = None

    @classmethod
    def from_settings(cls, config: AgentsConfig) -> AgentProfile | None:
        """Build the profile, or return ``None`` when it is disabled.

        Raises:
            ConfigurationError: If the registry is invalid.
            DependencyError: If the registry file cannot be read.
        """
        if not config.enabled:
            return None
        assert config.registry_path is not None  # noqa: S101 - enforced by AgentsConfig
        ordering = AssuranceOrdering(config.assurance_levels)
        limits = AgentLimits(
            max_hops=config.max_hops,
            ordering=ordering,
            default_assurance=config.default_assurance or ordering.lowest,
            require_replacement=config.require_replacement,
        )
        return cls(
            store=YamlAgentStore(config.registry_path, ordering=ordering),
            limits=limits,
            include_assurance=config.include_assurance,
            attr_store_ref=config.attr_store_ref,
        )

    def requester_record(self, workload: WorkloadIdentity) -> AgentRecord | None:
        """Return the agent record of the *authenticated* requesting workload, if it is an agent.

        agent-profile-03 §4.2.2 step 8 and §3.6.1: the requester is looked up by its client id
        (here, the workload id), then by agent id. The subject token's ``act`` is never used:
        it names the original actor, not the replacement requester.

        Raises:
            DependencyError: If the store cannot answer.
        """
        record = self.store.by_client_id(workload.id)
        return record if record is not None else self.store.get(workload.id)
