from __future__ import annotations

from pytrat import agents
from pytrat.core import AssuranceOrdering as CoreOrdering
from pytrat.core.assurance import DEFAULT_LEVELS as CORE_LEVELS
from pytrat.core.constants import SUPPORTED_DRAFTS


def test_package_is_marked_experimental_with_profile_version() -> None:
    assert SUPPORTED_DRAFTS["agent-profile"] == agents.PROFILE_VERSION
    assert agents.__doc__ is not None
    assert "experimental" in agents.__doc__.lower()
    assert agents.PROFILE_VERSION in agents.__doc__


def test_public_api_is_exported() -> None:
    for name in agents.__all__:
        assert hasattr(agents, name), name
    assert agents.AssuranceOrdering is CoreOrdering
    assert agents.DEFAULT_LEVELS is CORE_LEVELS
