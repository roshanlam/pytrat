"""PyTraT reference Transaction Token Service (TTS).

Implements the token endpoint of ``draft-ietf-oauth-transaction-tokens-11`` (RFC 8693 token
exchange with RFC 7523 workload authentication), replacement (§13.15), a hash-chained issuance
log, and the experimental agent profile via :mod:`pytrat.agents`.

This is the only PyTraT package that holds signing keys.
"""

from pytrat.server.agent_profile import AgentProfile
from pytrat.server.app import build_components, create_app, create_app_from_settings
from pytrat.server.audit_store import (
    AuditIntegrityError,
    AuditRecorder,
    InMemoryIssuanceLog,
    IssuanceLog,
    IssuanceRecord,
    SqliteIssuanceLog,
)
from pytrat.server.errors import OAuthError, OAuthErrorCode
from pytrat.server.forms import ClientAuthParams, TokenRequest, parse_token_request
from pytrat.server.ids import new_txn_id
from pytrat.server.issuance import IssuancePlan, plan_issuance
from pytrat.server.issuance_policy import IssuancePolicy, JsonType, WorkloadIssuanceRule
from pytrat.server.ratelimit import RateLimiter, TokenBucketRateLimiter
from pytrat.server.replacement import (
    ReplacementPlan,
    plan_replacement,
    txn_token_verifier,
    verify_txn_token,
)
from pytrat.server.settings import TtsSettings, load_settings, parse_settings
from pytrat.server.signing import FileKeySigner, KeyRingSigner, Signer, SigningKey
from pytrat.server.subjects import (
    JwtAccessTokenValidator,
    JwtIssuer,
    SelfSignedValidator,
    SubjectInfo,
    SubjectTokenValidator,
    UnsignedJsonValidator,
)
from pytrat.server.token_endpoint import TokenEndpoint, TokenResponse, TtsComponents
from pytrat.server.workloads import (
    CompositeAuthenticator,
    PrivateKeyJwtAuthenticator,
    TrustedProxyMtlsAuthenticator,
    WorkloadAuthenticator,
    WorkloadIdentity,
    WorkloadRegistry,
)

__all__ = [
    "AgentProfile",
    "AuditIntegrityError",
    "AuditRecorder",
    "ClientAuthParams",
    "CompositeAuthenticator",
    "FileKeySigner",
    "InMemoryIssuanceLog",
    "IssuanceLog",
    "IssuancePlan",
    "IssuancePolicy",
    "IssuanceRecord",
    "JsonType",
    "JwtAccessTokenValidator",
    "JwtIssuer",
    "KeyRingSigner",
    "OAuthError",
    "OAuthErrorCode",
    "PrivateKeyJwtAuthenticator",
    "RateLimiter",
    "ReplacementPlan",
    "SelfSignedValidator",
    "Signer",
    "SigningKey",
    "SqliteIssuanceLog",
    "SubjectInfo",
    "SubjectTokenValidator",
    "TokenBucketRateLimiter",
    "TokenEndpoint",
    "TokenRequest",
    "TokenResponse",
    "TrustedProxyMtlsAuthenticator",
    "TtsComponents",
    "TtsSettings",
    "UnsignedJsonValidator",
    "WorkloadAuthenticator",
    "WorkloadIdentity",
    "WorkloadIssuanceRule",
    "WorkloadRegistry",
    "build_components",
    "create_app",
    "create_app_from_settings",
    "load_settings",
    "new_txn_id",
    "parse_settings",
    "parse_token_request",
    "plan_issuance",
    "plan_replacement",
    "txn_token_verifier",
    "verify_txn_token",
]
