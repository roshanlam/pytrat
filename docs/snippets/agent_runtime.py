from pytrat.agents import (
    AgentRecord,
    AgentRequirements,
    InMemoryAgentStore,
    TokenProvider,
    ToolRuntime,
)
from pytrat.core import AuditSink

REPORT_AGENT = AgentRecord(
    id="report-agent",
    name="Quarterly report agent",
    owner="finance-platform",
    assurance_level="high",
    version="2.4.1",
    provenance="sha256:3f1c...",
)


def build_runtime(token_provider: TokenProvider, audit: AuditSink) -> ToolRuntime:
    runtime = ToolRuntime(
        agent=REPORT_AGENT,
        token_provider=token_provider,  # infrastructure code: obtains or replaces the token
        store=InMemoryAgentStore([REPORT_AGENT]),
        audit=audit,
        requirements=AgentRequirements(maximum_hops=3, require_verified_agent=True),
    )

    @runtime.protected_tool(scope="reports.read", resource="reports-api", minimum_assurance="low")
    def get_report(report_id: str, quarter: int) -> dict[str, str]:
        """Fetch one quarterly report."""
        # The tool never receives the token; the model never sees it.
        return {"report_id": report_id, "quarter": f"Q{quarter}", "status": "final"}

    return runtime
