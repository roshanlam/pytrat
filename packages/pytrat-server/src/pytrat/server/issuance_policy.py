"""The TTS issuance policy model (txn-tokens-11 §13.10).

txn-tokens-11 §13.10: "A TTS should be selective in which workloads can successfully request a
Txn-Token". This policy says, per registered workload, which scopes and audiences it may request,
how long its tokens may live, which ``request_details`` keys become ``tctx`` and which
``request_context`` keys become ``rctx`` (each with a required JSON type), and whether it may
request replacements. Anything not listed is denied or dropped.

This is *issuance* policy, distinct from the resource-side policy in ``pytrat.policy``.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from enum import StrEnum
from typing import Annotated, Final, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from pytrat.core.errors import ReasonCode, TokenError
from pytrat.core.scopes import Scope
from pytrat.server.errors import OAuthError, OAuthErrorCode

__all__ = [
    "RESERVED_RCTX_KEYS",
    "IssuancePolicy",
    "JsonType",
    "WorkloadIssuanceRule",
    "value_matches",
]

#: ``rctx`` members the TTS derives itself; a requester can never supply them.
RESERVED_RCTX_KEYS: Final = frozenset({"authn"})

_Key = Annotated[str, StringConstraints(min_length=1, max_length=128)]


class JsonType(StrEnum):
    """The JSON type an allowlisted context member must have."""

    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    OBJECT = "object"
    ARRAY = "array"
    NUMBER = "number"
    """Integer or float. PyTraT profile: floats are refused everywhere else (money safety)."""


def _has_float(value: object) -> bool:
    if isinstance(value, float):
        return True
    if isinstance(value, Mapping):
        return any(_has_float(item) for item in value.values())
    if isinstance(value, tuple | list):
        return any(_has_float(item) for item in value)
    return False


def value_matches(value: object, json_type: JsonType) -> bool:  # noqa: PLR0911 - one arm per type
    """Return True if ``value`` has exactly ``json_type``.

    Strict: ``True`` is not an integer, ``1.0`` is not an integer, and objects and arrays may not
    contain floats anywhere inside them (CLAUDE.md invariant 9).
    """
    match json_type:
        case JsonType.STRING:
            return isinstance(value, str)
        case JsonType.INTEGER:
            return isinstance(value, int) and not isinstance(value, bool)
        case JsonType.BOOLEAN:
            return isinstance(value, bool)
        case JsonType.OBJECT:
            return isinstance(value, Mapping) and not _has_float(value)
        case JsonType.ARRAY:
            return isinstance(value, tuple | list) and not _has_float(value)
        case JsonType.NUMBER:
            if isinstance(value, bool):
                return False
            return isinstance(value, int) or (isinstance(value, float) and math.isfinite(value))


class _Model(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True, hide_input_in_errors=True)


class WorkloadIssuanceRule(_Model):
    """What one workload may obtain.

    Attributes:
        scopes: Scopes the workload may request (granted scope is further limited by the subject).
        audiences: Audiences it may request; each must equal the Trust Domain. Empty means the
            Trust Domain only.
        max_lifetime_seconds: Lifetime cap for this workload's tokens, below the global one.
        tctx: ``request_details`` keys copied into ``tctx``, with their required JSON type.
        rctx: ``request_context`` keys copied into ``rctx``, with their required JSON type.
        may_replace: Whether the workload may present a Txn-Token for replacement.
    """

    scopes: tuple[_Key, ...] = Field(min_length=1)
    audiences: tuple[_Key, ...] = ()
    max_lifetime_seconds: Annotated[int, Field(ge=1, le=300)] | None = None
    tctx: dict[_Key, JsonType] = {}
    rctx: dict[_Key, JsonType] = {}
    may_replace: bool = False

    @model_validator(mode="after")
    def _check(self) -> Self:
        try:
            Scope.of(*self.scopes)
        except TokenError:
            raise ValueError("scopes must be valid RFC 6749 scope-tokens") from None
        if RESERVED_RCTX_KEYS.intersection(self.rctx):
            raise ValueError("rctx allowlist must not contain TTS-derived keys")
        return self

    @property
    def scope(self) -> Scope:
        """The permitted scopes as a :class:`Scope`."""
        return Scope.of(*self.scopes)


class IssuancePolicy(_Model):
    """Per-workload issuance rules. A workload without a rule obtains nothing.

    Attributes:
        workloads: Rules keyed by workload id.
        cap_lifetime_at_subject_exp: txn-tokens-11 §6 lets a Txn-Token outlive the presented
            subject token "subject to the policy of the TTS". PyTraT profile: by default it may
            not (``exp`` is capped at the subject's ``exp``); set False to allow it.
    """

    workloads: dict[_Key, WorkloadIssuanceRule] = {}
    cap_lifetime_at_subject_exp: bool = True

    def rule_for(self, workload_id: str) -> WorkloadIssuanceRule:
        """Return the rule for ``workload_id``.

        Raises:
            OAuthError: ``unauthorized_client`` / ``ISSUANCE_NOT_AUTHORIZED`` if there is none.
        """
        rule = self.workloads.get(workload_id)
        if rule is None:
            raise OAuthError(
                OAuthErrorCode.UNAUTHORIZED_CLIENT,
                "workload is not authorized to obtain Txn-Tokens",
                ReasonCode.ISSUANCE_NOT_AUTHORIZED,
            )
        return rule
