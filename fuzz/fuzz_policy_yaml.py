"""Fuzz the YAML resource-policy loader (``load_policy_text``).

Invariant: any text either compiles or raises :class:`ConfigurationError`; parser exceptions
(including YAML constructor errors and excessive nesting) never escape.
"""

from __future__ import annotations

from collections.abc import Iterator

from fuzz._harness import fuzz, text
from pytrat.core import ConfigurationError, InMemoryReplayStore
from pytrat.policy import load_policy_text

_REPLAY = InMemoryReplayStore()

_VALID = """\
version: 1
trust_domain: payments.internal
assurance_levels: [unverified, low, medium, high]
resources:
  - name: transfer
    path: /internal/transfer
    method: POST
    allowed_scopes: [payments.transfer]
    allowed_callers: [payment-service]
    bind_context: [source_account, amount_minor]
    agents: {enabled: true, maximum_hops: 3, minimum_assurance: medium}
  - name: posting
    path: /ledger/accounts/{account_id}/postings
    method: POST
    allowed_scopes: [ledger.post]
    bind_context: {account_id: source_account, amount.minor: amount_minor}
    single_use: true
  - name: health
    path: /internal/health
    method: GET
    require_transaction: false
"""


def TestOneInput(data: bytes) -> None:  # noqa: N802 - name required by Atheris
    """Load one policy document."""
    try:
        load_policy_text(
            text(data), expected_trust_domain="payments.internal", replay_store=_REPLAY
        )
    except ConfigurationError:
        return


def seeds() -> Iterator[bytes]:
    """A valid policy and malformed variations."""
    yield _VALID.encode()
    yield _VALID.replace("name: health", "name: transfer").encode()
    yield _VALID.replace("    method: GET\n", "    method: GET\n    method: POST\n").encode()
    yield _VALID.replace("medium}", "ultra}").encode()
    yield b"a: &a [1, 2]\nb: [*a, *a, *a]\n"
    yield b"version: 2001-12-14\n"
    # Regression: constructor errors and deep nesting escaped as ValueError / RecursionError.
    yield b"version: 2001-13-14\n"
    yield b"version: !!float x\n"
    yield b"version: !!int \n"
    yield b"version: !!bool x\n"
    yield b"[" * 700 + b"]" * 700
    yield b"version: !!binary AAAA\n"
    yield b"[" * 32 + b"]" * 32
    yield b"!!python/object:os.system {}\n"
    yield b""


if __name__ == "__main__":
    fuzz(TestOneInput)
