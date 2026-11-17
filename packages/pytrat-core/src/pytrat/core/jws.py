"""Verification of signed JWTs against trusted keys.

:func:`verify_jws` is the single signature-verification path in PyTraT. Transaction Tokens go
through it via :class:`~pytrat.core.validation.TokenVerifier`; the reference TTS uses it directly
for RFC 7523 client assertions and JWT subject tokens, which carry a different ``typ``.

It establishes authenticity only. Claim semantics (audience, lifetime, ...) are the caller's job.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from pytrat.core.constants import TXN_TOKEN_TYP
from pytrat.core.crypto import peek_header, verify_signature
from pytrat.core.errors import ReasonCode, TokenError
from pytrat.core.keys import KeyProvider, VerificationKey


@dataclass(frozen=True, slots=True)
class VerifiedJws:
    """A JWS whose signature was verified with a trusted key.

    Attributes:
        payload: The decoded, strictly parsed JSON payload object (not yet semantically checked).
        key: The trusted key that verified it.
        alg: The verified algorithm.
    """

    payload: Mapping[str, object]
    key: VerificationKey
    alg: str


def verify_jws(
    raw_token: str,
    keys: KeyProvider,
    *,
    algorithms: frozenset[str],
    allowed_typ: frozenset[str] | None = frozenset({TXN_TOKEN_TYP}),
    require_kid: bool = True,
    max_bytes: int = 16_384,
) -> VerifiedJws:
    """Check shape and header, select a trusted key, and verify the signature.

    Args:
        raw_token: Untrusted compact JWS.
        keys: Trusted keys, selected by ``kid``.
        algorithms: Allowlist; must not include ``none`` or ``HS*``.
        allowed_typ: Accepted ``typ`` values (compared case-insensitively, ``application/``
            optional). ``None`` skips the ``typ`` check, for tokens whose type is established by
            context (e.g. RFC 7523 client assertions).
        require_kid: Reject tokens without ``kid``.
        max_bytes: Reject larger tokens before parsing.

    Raises:
        TokenError: ``TOKEN_MALFORMED``, ``TOKEN_TYPE_INVALID``, ``ALGORITHM_NOT_ALLOWED``,
            ``KEY_UNKNOWN`` or ``SIGNATURE_INVALID``.
    """
    header = peek_header(raw_token, max_bytes=max_bytes, allowed_typ=allowed_typ)
    if header.alg not in algorithms:
        raise TokenError(ReasonCode.ALGORITHM_NOT_ALLOWED, "algorithm is not in the allowlist")
    if header.kid is None and require_kid:
        raise TokenError(ReasonCode.TOKEN_MALFORMED, "header kid is required")
    key = keys.get(header.kid)
    if key is None:
        raise TokenError(ReasonCode.KEY_UNKNOWN, "no trusted key matches the token kid")
    if header.alg not in key.algorithms:
        raise TokenError(ReasonCode.ALGORITHM_NOT_ALLOWED, "algorithm does not match the key")
    payload = verify_signature(raw_token, key.public_key, header.alg)
    return VerifiedJws(payload=payload, key=key, alg=header.alg)
