"""PyTraT core: Transaction Token models, verification, scopes, context binding and audit.

This package has no web-framework, HTTP-client or agent-profile dependencies.
"""

from pytrat.core._json import DuplicateKeyError, strict_loads
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
from pytrat.core.binding import BindingResult, BindingSpec, ContextBinding, Derived
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
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    DependencyError,
    PyTraTError,
    ReasonCode,
    TokenError,
)
from pytrat.core.jws import VerifiedJws, verify_jws
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
    "AuthenticationError",
    "AuthorizationError",
    "BindingResult",
    "BindingSpec",
    "ChainMetadata",
    "Clock",
    "ConfigurationError",
    "ContextBinding",
    "DependencyError",
    "Derived",
    "DuplicateKeyError",
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
    "VerifiedJws",
    "VerifiedToken",
    "VerifierSettings",
    "parse_claims",
    "replay_key",
    "strict_loads",
    "token_digest",
    "verify_jws",
]
