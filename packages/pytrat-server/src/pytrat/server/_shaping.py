"""Claim construction helpers shared by issuance and replacement (private, pure)."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from typing import Final

from pytrat.core.claims import JsonObject, TransactionClaims, parse_claims
from pytrat.core.errors import ReasonCode, TokenError
from pytrat.core.secret import SecretToken
from pytrat.server.errors import OAuthError, OAuthErrorCode
from pytrat.server.issuance_policy import JsonType, value_matches

# No "." allowed: a compact JWS (three dot-separated segments) can never pass as a key name.
_SAFE_KEY: Final = re.compile(r"[A-Za-z0-9_:-]{1,64}")
_MAX_RECORDED_KEYS: Final = 32


def safe_key_names(names: Iterable[str]) -> tuple[str, ...]:
    """Make requester-chosen key names safe to record in audit events.

    Names are attacker-controlled, so anything that is not a short identifier is replaced by a
    digest: a key name can never smuggle a token or other secret into the audit log.
    """
    safe = sorted(
        name
        if _SAFE_KEY.fullmatch(name)
        else f"sha256:{hashlib.sha256(name.encode()).hexdigest()[:16]}"
        for name in names
    )
    return tuple(safe[:_MAX_RECORDED_KEYS])


def dropped_key_names(dropped_tctx: Iterable[str], dropped_rctx: Iterable[str]) -> tuple[str, ...]:
    """Audit-safe, prefixed names of dropped ``tctx`` and ``rctx`` members."""
    return tuple(f"tctx.{name}" for name in safe_key_names(dropped_tctx)) + tuple(
        f"rctx.{name}" for name in safe_key_names(dropped_rctx)
    )


def filter_context(
    source: JsonObject | None, allowlist: Mapping[str, JsonType], *, label: str
) -> tuple[dict[str, object], tuple[str, ...]]:
    """Copy allowlisted members of a requester-supplied object.

    Returns:
        The copied members and the names of the dropped (unlisted) members.

    Raises:
        OAuthError: ``invalid_request`` / ``CLAIM_INVALID`` if an allowlisted member has the wrong
            JSON type (PyTraT profile: a mistyped value is refused, never coerced or dropped).
    """
    if source is None:
        return {}, ()
    kept: dict[str, object] = {}
    dropped: list[str] = []
    for key, value in source.items():
        json_type = allowlist.get(key)
        if json_type is None:
            dropped.append(key)
        elif not value_matches(value, json_type):
            raise OAuthError(
                OAuthErrorCode.INVALID_REQUEST,
                f"{label} member has the wrong JSON type",
                ReasonCode.CLAIM_INVALID,
            )
        else:
            kept[key] = value
    return kept, tuple(dropped)


def build_claims(payload: Mapping[str, object], subject_token: SecretToken) -> TransactionClaims:
    """Validate the planned payload as :class:`TransactionClaims`.

    Raises:
        OAuthError: ``invalid_request`` if the claims are not valid (for example an over-long
            ``sub``), or if the subject token appears anywhere in them (txn-tokens-11 §13.4: the
            Txn-Token MUST NOT contain the presented access token).
    """
    serialized = json.dumps(_thaw(payload), separators=(",", ":"))
    if subject_token.reveal() in serialized:
        raise OAuthError(
            OAuthErrorCode.INVALID_REQUEST,
            "the subject token must not be embedded in the Txn-Token",
            ReasonCode.CLAIM_INVALID,
        )
    try:
        return parse_claims(payload)
    except TokenError as exc:
        raise OAuthError(OAuthErrorCode.INVALID_REQUEST, exc.detail, exc.reason) from None


def _thaw(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_thaw(item) for item in value]
    return value


def lifetime_seconds(global_seconds: int, workload_max: int | None) -> int:
    """The lifetime cap for a token: the global lifetime, lowered by the workload's maximum."""
    return global_seconds if workload_max is None else min(global_seconds, workload_max)
