from __future__ import annotations

from collections.abc import Callable

import pytest

from pytrat.core import VerifiedToken
from pytrat.core.testing import TokenFactory

type Mint = Callable[..., VerifiedToken]


@pytest.fixture(scope="session")
def factory() -> TokenFactory:
    return TokenFactory.create()


@pytest.fixture(scope="session")
def mint(factory: TokenFactory) -> Mint:
    verifier = factory.verifier()

    def _mint(**claims: object) -> VerifiedToken:
        return verifier.verify(factory.mint(**claims))

    return _mint
