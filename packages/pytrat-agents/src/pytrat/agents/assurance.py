"""Assurance ordering for the agent profile.

agent-profile-03 §3.5.1: "Deployments MUST define their own ordered set and comparison function".
The implementation lives in :mod:`pytrat.core.assurance` because resource-side policy and the TTS
both need it; this module re-exports it so agent-profile users have a single import location.
"""

from __future__ import annotations

from pytrat.core.assurance import DEFAULT_LEVELS, AssuranceOrdering

__all__ = ["DEFAULT_LEVELS", "AssuranceOrdering"]
