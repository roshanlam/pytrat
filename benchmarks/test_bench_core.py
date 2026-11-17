"""Local verification benchmarks (no network).

Run with:  uv run pytest benchmarks --benchmark-only
These measure local CPU cost only; remote token exchange is benchmarked separately.
"""

from __future__ import annotations

import pytest

from pytrat.core import ContextBinding, VerifierSettings
from pytrat.core.testing import TokenFactory

ALGORITHMS = ["ES256", "EdDSA", "PS256"]
FIELDS = ["source_account", "destination_account", "amount_minor", "currency"]
REQUEST = {
    "source_account": "account-A",
    "destination_account": "account-B",
    "amount_minor": 10000,
    "currency": "USD",
}


@pytest.mark.parametrize("alg", ALGORITHMS)
def test_verify(benchmark, alg: str) -> None:
    factory = TokenFactory.create(alg)
    verifier = factory.verifier()
    token = factory.mint()
    result = benchmark(verifier.verify, token)
    assert result.claims.aud == "payments.internal"


def test_verify_cached_repeat(benchmark) -> None:
    factory = TokenFactory.create("ES256")
    settings = VerifierSettings(
        trust_domain="payments.internal", algorithms=frozenset({"ES256"}), cache_size=1024
    )
    verifier = factory.verifier(settings)
    token = factory.mint()
    verifier.verify(token)
    benchmark(verifier.verify, token)


def test_context_binding(benchmark) -> None:
    factory = TokenFactory.create("ES256")
    tctx = factory.verifier().verify(factory.mint()).claims.tctx
    binding = ContextBinding.compile(FIELDS)
    benchmark(binding.check, tctx, REQUEST)
