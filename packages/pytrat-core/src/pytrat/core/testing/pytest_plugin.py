"""pytest plugin: ready-made fixtures for testing services protected by PyTraT.

Installed automatically with ``pytrat-core`` (a ``pytest11`` entry point), so tests can use the
fixtures without importing anything:

* ``pytrat_kit``: a :class:`TransactionTestKit` that stands in for the TTS and for calling
  workloads.
* ``pytrat_trust_domain``: the Trust Domain the kit mints tokens for. Override it in a
  ``conftest.py`` to match your service.

Test-only: like the rest of :mod:`pytrat.core.testing`, never import this from production code.
"""

from __future__ import annotations

import secrets
from collections.abc import Mapping

import pytest

from pytrat.core.clock import FrozenClock, SystemClock
from pytrat.core.constants import TXN_TOKEN_HEADER, TXN_TOKEN_TYP
from pytrat.core.crypto import sign_compact
from pytrat.core.keys import StaticKeySet
from pytrat.core.testing import TestKey, TokenFactory, generate_test_key
from pytrat.core.validation import TokenVerifier, VerifierSettings
from pytrat.core.workload import DEFAULT_WORKLOAD_JWT_HEADER, WorkloadKeys

__all__ = ["TransactionTestKit", "pytrat_kit", "pytrat_trust_domain"]

_WORKLOAD_JWT_TYP = "wit+jwt"
_WORKLOAD_JWT_LIFETIME = 60
_ALG = "ES256"  # accepted by default by both TokenVerifier and WorkloadJwtAuthenticator


class TransactionTestKit:
    """Stands in for the Transaction Token Service and for the workloads that call your service.

    Every key is generated per kit, held in memory, and never written to disk. Tokens are issued at
    the current wall-clock time, so services under test can use their normal clock.

    Typical use: build the app with :meth:`tts_keys` and :meth:`workload_keys`, then send requests
    with :meth:`headers`.
    """

    __test__ = False  # not a pytest test class

    def __init__(self, *, trust_domain: str) -> None:
        self.trust_domain = trust_domain
        self._clock = FrozenClock(SystemClock().now())
        self.factory = TokenFactory(
            key=generate_test_key(_ALG, kid="test-tts"),
            trust_domain=trust_domain,
            clock=self._clock,
            defaults={"sub": "user:test", "req_wl": "test-gateway"},
        )
        self._workloads: dict[str, TestKey] = {}

    def tts_keys(self) -> StaticKeySet:
        """The keys a service must trust to verify this kit's Transaction Tokens."""
        return self.factory.key.key_set()

    def verifier(self) -> TokenVerifier:
        """A :class:`TokenVerifier` for :attr:`trust_domain` that trusts :meth:`tts_keys`."""
        settings = VerifierSettings(trust_domain=self.trust_domain, algorithms=frozenset({_ALG}))
        return TokenVerifier(settings, self.tts_keys())

    def workload_keys(self, *workload_ids: str) -> WorkloadKeys:
        """Trusted keys for the named calling workloads, generating each key on first use."""
        return WorkloadKeys(
            {workload_id: self._workload(workload_id).key_set() for workload_id in workload_ids}
        )

    def token(
        self,
        *,
        scope: str,
        tctx: Mapping[str, object] | None = None,
        rctx: Mapping[str, object] | None = None,
        **claims: object,
    ) -> str:
        """A signed, currently valid Transaction Token.

        Args:
            scope: The authorized scope.
            tctx: Transaction context the service binds the request to. Omitted when ``None``.
            rctx: Request context. Omitted when ``None``.
            **claims: Any other claim, e.g. ``sub="user:42"``; a value of ``None`` removes the
                claim, which is how to test a malformed token.
        """
        return self._mint({"scope": scope, "tctx": tctx, "rctx": rctx, **claims})

    def workload_jwt(self, workload_id: str, *, audience: str) -> str:
        """A workload JWT proving ``workload_id`` is calling the service named ``audience``.

        This is what ``pytrat.client.WorkloadJwtAuth`` sends in production.
        """
        key = self._workload(workload_id)
        now = int(SystemClock().now())
        claims = {
            "sub": workload_id,
            "aud": audience,
            "iat": now,
            "exp": now + _WORKLOAD_JWT_LIFETIME,
            "jti": secrets.token_urlsafe(16),
        }
        return sign_compact(
            claims, key.private_key, alg=key.alg, kid=key.kid, typ=_WORKLOAD_JWT_TYP
        )

    def headers(
        self,
        *,
        scope: str,
        caller: str | None = None,
        audience: str | None = None,
        tctx: Mapping[str, object] | None = None,
        **claims: object,
    ) -> dict[str, str]:
        """Request headers carrying a Transaction Token and, optionally, a calling workload.

        Args:
            scope: The authorized scope.
            caller: Workload to authenticate as. Requires ``audience``. Without it, the request
                carries no workload credential.
            audience: The service being called, as configured in its workload authenticator.
            tctx: Transaction context the service binds the request to.
            **claims: Further claims for :meth:`token`.

        Raises:
            ValueError: If ``caller`` is given without ``audience``.
        """
        token = self._mint({"scope": scope, "tctx": tctx, "rctx": None, **claims})
        headers = {TXN_TOKEN_HEADER: token}
        if caller is not None:
            if audience is None:
                raise ValueError("audience is required with caller: name the service being called")
            headers[DEFAULT_WORKLOAD_JWT_HEADER] = self.workload_jwt(caller, audience=audience)
        return headers

    def _mint(self, claim_overrides: Mapping[str, object]) -> str:
        # Overrides are claims only: no keyword can select a different signing key or header.
        self._clock.set(SystemClock().now())
        key = self.factory.key
        payload = self.factory.claims(**claim_overrides)
        return sign_compact(payload, key.private_key, alg=key.alg, kid=key.kid, typ=TXN_TOKEN_TYP)

    def _workload(self, workload_id: str) -> TestKey:
        if workload_id not in self._workloads:
            self._workloads[workload_id] = generate_test_key(_ALG, kid=workload_id)
        return self._workloads[workload_id]

    def __repr__(self) -> str:
        return f"TransactionTestKit(trust_domain={self.trust_domain!r})"


@pytest.fixture
def pytrat_trust_domain() -> str:
    """The Trust Domain tokens are minted for. Override this fixture to match your service."""
    return "example.internal"


@pytest.fixture
def pytrat_kit(pytrat_trust_domain: str) -> TransactionTestKit:
    """A fresh :class:`TransactionTestKit` for each test."""
    return TransactionTestKit(trust_domain=pytrat_trust_domain)
