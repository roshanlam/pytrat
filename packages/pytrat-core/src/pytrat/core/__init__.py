"""PyTraT core: Transaction Token models, verification, scopes, context binding and audit.

This package has no web-framework, HTTP-client or agent-profile dependencies.
"""

from pytrat.core.assurance import AssuranceOrdering
from pytrat.core.audit import (
    AgentAuditContext,
    AuditEvent,
    AuditSink,
    EventType,
    JsonLinesSink,
    LoggingSink,
    MemorySink,
    NullSink,
)
from pytrat.core.binding import BindingResult, ContextBinding, Derived
from pytrat.core.claims import (
    AgenticContext,
    AgentIdentity,
    ChainMetadata,
    JsonObject,
    TransactionClaims,
    parse_claims,
)
from pytrat.core.clock import Clock, FrozenClock, SystemClock
from pytrat.core.constants import SUPPORTED_DRAFTS, TXN_TOKEN_HEADER, TXN_TOKEN_TYP
from pytrat.core.errors import (
    AuthorizationError,
    ConfigurationError,
    DependencyError,
    PyTraTError,
    ReasonCode,
    TokenError,
)
from pytrat.core.keys import KeyProvider, StaticKeySet, VerificationKey
from pytrat.core.replay import InMemoryReplayStore, ReplayStore, replay_key
from pytrat.core.scopes import Scope
from pytrat.core.secret import SecretToken, token_digest
from pytrat.core.validation import TokenVerifier, VerifiedToken, VerifierSettings

__all__ = [
    "SUPPORTED_DRAFTS",
    "TXN_TOKEN_HEADER",
    "TXN_TOKEN_TYP",
    "AgentAuditContext",
    "AgentIdentity",
    "AgenticContext",
    "AssuranceOrdering",
    "AuditEvent",
    "AuditSink",
    "AuthorizationError",
    "BindingResult",
    "ChainMetadata",
    "Clock",
    "ConfigurationError",
    "ContextBinding",
    "DependencyError",
    "Derived",
    "EventType",
    "FrozenClock",
    "InMemoryReplayStore",
    "JsonLinesSink",
    "JsonObject",
    "KeyProvider",
    "LoggingSink",
    "MemorySink",
    "NullSink",
    "PyTraTError",
    "ReasonCode",
    "ReplayStore",
    "Scope",
    "SecretToken",
    "StaticKeySet",
    "SystemClock",
    "TokenError",
    "TokenVerifier",
    "TransactionClaims",
    "VerificationKey",
    "VerifiedToken",
    "VerifierSettings",
    "parse_claims",
    "replay_key",
    "token_digest",
]
