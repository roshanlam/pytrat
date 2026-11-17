"""Builds the TransactionEnforcer named by ``PYTRAT['ENFORCER']``."""

import os

from pytrat.core import (
    LoggingSink,
    StaticKeySet,
    TokenVerifier,
    VerifierSettings,
    WorkloadJwtAuthenticator,
)
from pytrat.policy import TransactionEnforcer


def build_enforcer() -> TransactionEnforcer:
    """Trust the TTS keys for Txn-Tokens and the workload keys for caller identity."""
    tts_keys = StaticKeySet.from_jwks_file(os.environ["LEDGER_TTS_JWKS"])
    workload_keys = StaticKeySet.from_jwks_file(os.environ["LEDGER_WORKLOAD_JWKS"])
    return TransactionEnforcer(
        service="ledger",
        verify=TokenVerifier(VerifierSettings(trust_domain="payments.internal"), tts_keys),
        authenticator=WorkloadJwtAuthenticator(workload_keys, audience="ledger"),
        audit=LoggingSink(),
    )
