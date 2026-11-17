from __future__ import annotations

import pytest

from pytrat.core import TokenVerifier
from pytrat.core.testing import TestKey, TokenFactory, generate_test_key


@pytest.fixture(scope="session")
def es256_key() -> TestKey:
    return generate_test_key("ES256", kid="es256-key")


@pytest.fixture
def factory(es256_key: TestKey) -> TokenFactory:
    return TokenFactory(key=es256_key)


@pytest.fixture
def verifier(factory: TokenFactory) -> TokenVerifier:
    return factory.verifier()
