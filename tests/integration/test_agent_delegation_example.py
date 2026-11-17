"""The agent-delegation example as a test.

Assurance cannot be laundered through a trusted agent (agent-profile-03 §3.5.1).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[2] / "examples" / "agent-delegation"))

from agent_delegation import run

pytestmark = pytest.mark.integration


async def test_low_assurance_origin_cannot_gain_authority_through_trusted_agent(tmp_path) -> None:
    outcomes = await run(tmp_path)
    assert outcomes == {
        "delegated": "DENIED (AGENT_ASSURANCE_INSUFFICIENT)",
        "direct": "ALLOWED",
        "third_hop": "REFUSED (invalid_grant)",
    }
