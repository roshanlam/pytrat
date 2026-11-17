"""TTS configuration: a strict, frozen Pydantic model loaded once at startup.

Invalid configuration raises :class:`~pytrat.core.errors.ConfigurationError` and the process
refuses to start. Unknown keys are rejected (``extra="forbid"``) so typos fail loudly.

YAML is decoded with ``yaml.safe_load`` and then validated in Pydantic's strict *JSON* mode, so
YAML-only types (dates, binary, ...) are rejected and lists map to tuples. Relative paths are
resolved against the directory of the YAML file.
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Final, Self
from urllib.parse import urlsplit

import yaml
from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    ValidationInfo,
    model_validator,
)

from pytrat.core.assurance import DEFAULT_LEVELS
from pytrat.core.constants import FORBIDDEN_ALGORITHMS, SUPPORTED_ALGORITHMS
from pytrat.core.errors import ConfigurationError
from pytrat.server.issuance_policy import IssuancePolicy

__all__ = [
    "AgentsConfig",
    "JwtIssuerConfig",
    "KeyState",
    "RateLimitConfig",
    "ReplacementConfig",
    "SelfSignedConfig",
    "SigningKeyConfig",
    "SubjectTokensConfig",
    "TrustedProxyConfig",
    "TtsSettings",
    "UnsignedJsonConfig",
    "WorkloadAuthConfig",
    "WorkloadConfig",
    "load_settings",
    "parse_settings",
]

#: PyTraT profile P3: Txn-Tokens live "on the order of minutes or less" (txn-tokens-11 §6).
MAX_TOKEN_LIFETIME_SECONDS: Final = 300


def _resolve_path(value: Path, info: ValidationInfo) -> Path:
    base_dir = info.context.get("base_dir") if isinstance(info.context, Mapping) else None
    if value.is_absolute() or not isinstance(base_dir, Path):
        return value
    return base_dir / value


ConfigPath = Annotated[Path, AfterValidator(_resolve_path)]
NonEmptyStr = Annotated[str, StringConstraints(min_length=1, max_length=2048)]


class _Model(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True, hide_input_in_errors=True)


class KeyState(StrEnum):
    """Lifecycle state of a signing key."""

    ACTIVE = "active"
    """Signs new tokens and is published."""
    RETIRING = "retiring"
    """No longer signs; still published so tokens it signed keep verifying until they expire."""


class SigningKeyConfig(_Model):
    """One TTS signing key."""

    kid: NonEmptyStr
    alg: NonEmptyStr
    private_key_path: ConfigPath
    state: KeyState = KeyState.ACTIVE


class WorkloadConfig(_Model):
    """A registered workload and the public keys it authenticates with (RFC 7523)."""

    id: NonEmptyStr
    jwks_path: ConfigPath | None = None
    jwks: dict[str, object] | None = None
    allowed_audiences: tuple[NonEmptyStr, ...] | None = None

    @model_validator(mode="after")
    def _check(self) -> Self:
        # PyTraT profile P5: ',' separates the agent-profile req_wl chain, so it is forbidden here.
        if "," in self.id:
            raise ValueError("workload id must not contain ','")
        if (self.jwks_path is None) == (self.jwks is None):
            raise ValueError("exactly one of jwks_path or jwks must be set")
        return self


class JwtIssuerConfig(_Model):
    """A trusted issuer of JWT access tokens accepted as subject tokens."""

    issuer: NonEmptyStr
    jwks_path: ConfigPath
    audience: NonEmptyStr
    algorithms: tuple[NonEmptyStr, ...] = ("ES256",)


class SelfSignedConfig(_Model):
    """Self-signed subject tokens (txn-tokens-11 §11.2.1)."""

    enabled: bool = False
    max_age_seconds: Annotated[int, Field(ge=1, le=3600)] = 300


class UnsignedJsonConfig(_Model):
    """Unsigned JSON subject tokens (txn-tokens-11 §11.2.2); off unless workloads are listed."""

    allowed_workloads: tuple[NonEmptyStr, ...] = ()


class SubjectTokensConfig(_Model):
    """Accepted subject token types."""

    jwt_access_token: tuple[JwtIssuerConfig, ...] = ()
    self_signed: SelfSignedConfig = SelfSignedConfig()
    unsigned_json: UnsignedJsonConfig = UnsignedJsonConfig()


class ReplacementConfig(_Model):
    """Replacement policy (txn-tokens-11 §13.15)."""

    extend_lifetime: bool = False
    max_replacements_per_txn: Annotated[int, Field(ge=1, le=1000)] = 10


class AgentsConfig(_Model):
    """Agent profile (agent-profile-03). Disabled by default."""

    enabled: bool = False
    max_hops: Annotated[int, Field(ge=1, le=10_000)] = 5
    assurance_levels: tuple[NonEmptyStr, ...] = DEFAULT_LEVELS
    default_assurance: NonEmptyStr | None = None
    registry_path: ConfigPath | None = None
    include_assurance: bool = True
    require_replacement: bool = True
    attr_store_ref: NonEmptyStr | None = None

    @model_validator(mode="after")
    def _check(self) -> Self:
        if self.enabled and self.registry_path is None:
            raise ValueError("agents.registry_path is required when agents are enabled")
        if len(set(self.assurance_levels)) != len(self.assurance_levels):
            raise ValueError("assurance_levels must be unique")
        if self.default_assurance is not None and self.default_assurance not in (
            self.assurance_levels
        ):
            raise ValueError("default_assurance must be one of assurance_levels")
        return self


class RateLimitConfig(_Model):
    """Per-workload token bucket."""

    requests_per_second: Annotated[float, Field(gt=0, le=1_000_000)] = 50.0
    burst: Annotated[int, Field(ge=1, le=1_000_000)] = 100


class TrustedProxyConfig(_Model):
    """Workload identity asserted by a TLS-terminating proxy in a request header."""

    header: NonEmptyStr
    trusted_cidrs: tuple[NonEmptyStr, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _check(self) -> Self:
        for cidr in self.trusted_cidrs:
            try:
                ipaddress.ip_network(cidr, strict=True)
            except ValueError:
                raise ValueError("trusted_cidrs must contain valid CIDR blocks") from None
        return self


class WorkloadAuthConfig(_Model):
    """Workload authentication methods (txn-tokens-11 §11.5)."""

    private_key_jwt: bool = True
    max_assertion_lifetime_seconds: Annotated[int, Field(ge=1, le=300)] = 300
    trusted_proxy: TrustedProxyConfig | None = None

    @model_validator(mode="after")
    def _check(self) -> Self:
        if not self.private_key_jwt and self.trusted_proxy is None:
            raise ValueError("at least one workload authentication method must be enabled")
        return self


class TtsSettings(_Model):
    """Complete TTS configuration. See ``examples/tts.yaml`` for an annotated example."""

    trust_domain: NonEmptyStr
    issuer: NonEmptyStr
    token_endpoint: NonEmptyStr
    token_lifetime_seconds: Annotated[int, Field(ge=1, le=MAX_TOKEN_LIFETIME_SECONDS)] = 60
    leeway_seconds: Annotated[int, Field(ge=0, le=60)] = 5
    algorithms: tuple[NonEmptyStr, ...] = ("ES256",)
    signing_keys: tuple[SigningKeyConfig, ...] = Field(min_length=1)
    workloads: tuple[WorkloadConfig, ...] = ()
    workload_auth: WorkloadAuthConfig = WorkloadAuthConfig()
    subject_tokens: SubjectTokensConfig = SubjectTokensConfig()
    issuance_policy: IssuancePolicy = IssuancePolicy()
    replacement: ReplacementConfig = ReplacementConfig()
    agents: AgentsConfig = AgentsConfig()
    audit_db_path: ConfigPath | None = None
    rate_limit: RateLimitConfig = RateLimitConfig()
    max_request_bytes: Annotated[int, Field(ge=1024, le=1_048_576)] = 32_768

    @model_validator(mode="after")
    def _check(self) -> Self:
        _check_url(self.token_endpoint)
        self._check_algorithms()
        self._check_signing_keys()
        self._check_workloads()
        return self

    def _check_algorithms(self) -> None:
        algorithms = set(self.algorithms)
        for issuer in self.subject_tokens.jwt_access_token:
            algorithms.update(issuer.algorithms)
        # PyTraT profile P1: none and HS* can never be enabled.
        if algorithms & FORBIDDEN_ALGORITHMS:
            raise ValueError("algorithms 'none' and HS* can never be enabled")
        if algorithms - SUPPORTED_ALGORITHMS:
            raise ValueError("unsupported algorithm configured")

    def _check_signing_keys(self) -> None:
        kids = [key.kid for key in self.signing_keys]
        if len(set(kids)) != len(kids):
            raise ValueError("signing key kids must be unique")
        if sum(key.state is KeyState.ACTIVE for key in self.signing_keys) != 1:
            raise ValueError("exactly one signing key must be active")
        if any(key.alg not in self.algorithms for key in self.signing_keys):
            raise ValueError("every signing key alg must be listed in algorithms")

    def _check_workloads(self) -> None:
        ids = [workload.id for workload in self.workloads]
        if len(set(ids)) != len(ids):
            raise ValueError("workload ids must be unique")
        registered = set(ids)
        if set(self.issuance_policy.workloads) - registered:
            raise ValueError("issuance_policy names a workload that is not registered")
        if set(self.subject_tokens.unsigned_json.allowed_workloads) - registered:
            raise ValueError("unsigned_json.allowed_workloads names an unregistered workload")
        audiences = [
            audience for workload in self.workloads for audience in workload.allowed_audiences or ()
        ] + [
            audience
            for rule in self.issuance_policy.workloads.values()
            for audience in rule.audiences
        ]
        # txn-tokens-11 §11.1: audience MUST be the Trust Domain name.
        if any(audience != self.trust_domain for audience in audiences):
            raise ValueError("every allowed audience must equal trust_domain")

    def workload(self, workload_id: str) -> WorkloadConfig | None:
        """Return the registered workload ``workload_id``, if any."""
        return next((w for w in self.workloads if w.id == workload_id), None)


def _check_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme not in {"https", "http"} or not parts.netloc or parts.fragment:
        raise ValueError("token_endpoint must be an absolute http(s) URL")


def parse_settings(data: Mapping[str, object], base_dir: Path | None = None) -> TtsSettings:
    """Validate a decoded configuration document.

    Args:
        data: The decoded document (e.g. from YAML).
        base_dir: Directory against which relative paths resolve.

    Raises:
        ConfigurationError: If the document is invalid. The detail names the failing location.
    """
    try:
        document = json.dumps(data, allow_nan=False)
    except (TypeError, ValueError):
        raise ConfigurationError("configuration contains values that are not plain JSON") from None
    try:
        return TtsSettings.model_validate_json(document, context={"base_dir": base_dir})
    except ValidationError as exc:
        first = exc.errors(include_input=False, include_url=False)[0]
        where = ".".join(str(part) for part in first["loc"]) or "document"
        raise ConfigurationError(f"configuration '{where}' is invalid: {first['msg']}") from None


def load_settings(path: str | Path) -> TtsSettings:
    """Load and validate a YAML configuration file.

    Relative paths inside the file resolve against the file's directory.

    Raises:
        ConfigurationError: If the file cannot be read or is invalid.
    """
    config_path = Path(path).resolve()
    try:
        raw_text = config_path.read_text(encoding="utf-8")
    except OSError:
        raise ConfigurationError("configuration file could not be read") from None
    try:
        raw_document = yaml.safe_load(raw_text)
    except yaml.YAMLError:
        raise ConfigurationError("configuration file is not valid YAML") from None
    if not isinstance(raw_document, Mapping):
        raise ConfigurationError("configuration file must contain a mapping")
    return parse_settings(raw_document, base_dir=config_path.parent)
