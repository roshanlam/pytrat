"""Typed Transaction Token claims.

Raw payloads are parsed exactly once, at the trust boundary, into these immutable models.
Downstream code never handles a ``dict`` of claims.

txn-tokens-11 §9.2: recipients MUST ignore claims they do not understand, so unknown claims are
dropped rather than rejected (``extra="ignore"``).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Annotated

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PlainSerializer,
    PlainValidator,
    StringConstraints,
    ValidationError,
)

from pytrat.core._json import JsonObject, freeze_object, thaw
from pytrat.core.errors import ReasonCode, TokenError
from pytrat.core.scopes import Scope

__all__ = [
    "AgentIdentity",
    "AgenticContext",
    "ChainMetadata",
    "JsonObject",
    "TransactionClaims",
    "parse_claims",
]

_MAX_IDENTIFIER = 2048

NonEmptyStr = Annotated[str, StringConstraints(min_length=1, max_length=_MAX_IDENTIFIER)]
NumericDate = Annotated[int, Field(ge=0, le=2**53)]


def _validate_scope(value: object) -> Scope:
    if isinstance(value, Scope):
        return value
    if not isinstance(value, str):
        raise ValueError("scope must be a string")  # noqa: TRY004 - pydantic expects ValueError
    try:
        return Scope.parse(value)
    except TokenError as exc:
        raise ValueError(exc.detail) from None


def _validate_object(value: object) -> JsonObject:
    try:
        return freeze_object(value)
    except TypeError as exc:
        raise ValueError(str(exc)) from None


ScopeClaim = Annotated[Scope, PlainValidator(_validate_scope), PlainSerializer(str)]
ObjectClaim = Annotated[JsonObject, PlainValidator(_validate_object), PlainSerializer(thaw)]


class _Claims(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        strict=True,
        extra="ignore",
        arbitrary_types_allowed=True,
        hide_input_in_errors=True,
    )


class AgentIdentity(_Claims):
    """An agent reference inside ``agentic_ctx`` (agent-profile-03 §3.5.1).

    ``session_id`` is self-asserted and informational only. It MUST NOT be used as an
    authorization criterion (agent-profile-03 §3.5.4).
    """

    id: NonEmptyStr
    session_id: NonEmptyStr | None = None


class ChainMetadata(_Claims):
    """Chain bookkeeping inside ``agentic_ctx`` (agent-profile-03 §3.5.1)."""

    # agent-profile-03 §3.5.1: set to 1 at initial issuance, incremented per agent replacement.
    hop_count: Annotated[int, Field(ge=1, le=10_000)]
    min_assurance_level: NonEmptyStr | None = None


class AgenticContext(_Claims):
    """The ``agentic_ctx`` claim (agent-profile-03 §3.5).

    Unknown members are ignored (agent-profile-03 §3.5.4).
    """

    originator: AgentIdentity
    proximate_agent: AgentIdentity
    chain_metadata: ChainMetadata
    attr_store_ref: NonEmptyStr | None = None


class TransactionClaims(_Claims):
    """The verified payload of a Transaction Token (txn-tokens-11 §9.2)."""

    aud: NonEmptyStr
    """Trust Domain in which the token is valid. A single string: one token, one Trust Domain."""
    txn: NonEmptyStr
    """Unique transaction identifier."""
    sub: NonEmptyStr
    """Transaction principal, unique within the Trust Domain."""
    scope: ScopeClaim
    """Purpose of the transaction."""
    req_wl: NonEmptyStr
    """Requesting workload. Under the agent profile, a comma-separated chain (PyTraT profile P5)."""
    iat: NumericDate
    exp: NumericDate
    iss: NonEmptyStr | None = None
    tctx: ObjectClaim | None = None
    """Immutable, TTS-authoritative transaction details."""
    rctx: ObjectClaim | None = None
    """TTS-authoritative request context."""
    act: ObjectClaim | None = None
    """Delegated actor (RFC 8693 §4.1), preserved unchanged by the agent profile."""
    agentic_ctx: AgenticContext | None = None

    @property
    def id(self) -> str:
        """Alias for ``txn``."""
        return self.txn

    @property
    def trust_domain(self) -> str:
        """Alias for ``aud``."""
        return self.aud

    @property
    def requesting_workloads(self) -> tuple[str, ...]:
        """The recorded workload chain.

        PyTraT profile P5: the base draft defines ``req_wl`` as one string; the agent profile
        appends with commas. The chain is split only when ``agentic_ctx`` is present.
        """
        if self.agentic_ctx is None:
            return (self.req_wl,)
        return tuple(self.req_wl.split(","))

    @property
    def actor(self) -> str | None:
        """``act.sub`` if present and a string."""
        if self.act is None:
            return None
        actor = self.act.get("sub")
        return actor if isinstance(actor, str) else None

    def to_payload(self) -> dict[str, object]:
        """Return the JSON payload, omitting absent optional claims."""
        return self.model_dump(mode="json", exclude_none=True)


def parse_claims(payload: Mapping[str, object]) -> TransactionClaims:
    """Parse a decoded JWT payload into :class:`TransactionClaims`.

    Raises:
        TokenError: ``CLAIM_MISSING`` if a required claim is absent, ``CLAIM_INVALID`` if any claim
            has the wrong type or value. The detail names the claim, never its value.
    """
    try:
        return TransactionClaims.model_validate(payload)
    except ValidationError as exc:
        first = exc.errors(include_input=False, include_url=False)[0]
        claim = ".".join(str(part) for part in first["loc"]) or "payload"
        # A missing member inside a present claim makes that claim invalid, not missing.
        if first["type"] == "missing" and len(first["loc"]) == 1:
            raise TokenError(
                ReasonCode.CLAIM_MISSING, f"required claim '{claim}' is missing"
            ) from None
        raise TokenError(ReasonCode.CLAIM_INVALID, f"claim '{claim}' is invalid") from None
