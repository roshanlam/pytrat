"""PyTraT policy: YAML policy model, compiler and evaluator.

Load a policy at startup, then look up and evaluate the route policy per request::

    policy_set = load_policy("policy.yaml", expected_trust_domain="payments.internal")
    decision = policy_set.for_route("POST", "/internal/transfer").evaluate(
        AuthorizationRequest(token=verified, caller=workload_id, request_data=body)
    )

Routes without a policy are denied (``POLICY_NOT_FOUND``).
"""

from pytrat.policy.compiler import (
    SUPPORTED_VERSIONS,
    AgentRequirements,
    CompiledPolicy,
    compile_policy,
)
from pytrat.policy.evaluator import (
    HTTP_METHODS,
    AgentDirectory,
    AuthorizationRequest,
    Decision,
    PolicyEvaluator,
    PolicySet,
    RouteTemplate,
)
from pytrat.policy.loader import PolicySource, load_policy, load_policy_text
from pytrat.policy.model import AgentsModel, BindContext, PolicyDocument, ResourceModel

__all__ = [
    "HTTP_METHODS",
    "SUPPORTED_VERSIONS",
    "AgentDirectory",
    "AgentRequirements",
    "AgentsModel",
    "AuthorizationRequest",
    "BindContext",
    "CompiledPolicy",
    "Decision",
    "PolicyDocument",
    "PolicyEvaluator",
    "PolicySet",
    "PolicySource",
    "ResourceModel",
    "RouteTemplate",
    "compile_policy",
    "load_policy",
    "load_policy_text",
]
