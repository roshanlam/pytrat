"""Subject token validation (txn-tokens-11 §11.2, §11.3).

txn-tokens-11 §11.3: "The TTS MUST validate the subject_token, including verifying the signature,
if it is signed." Each supported ``subject_token_type`` has one :class:`SubjectTokenValidator`.
Validators return a :class:`SubjectInfo` holding only what issuance needs; the subject token
itself is never retained, so it can never be embedded in a Txn-Token (txn-tokens-11 §13.4).

Every failure is ``invalid_grant``.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Final, Protocol

from pytrat.core.claims import JsonObject
from pytrat.core.clock import Clock
from pytrat.core.errors import ConfigurationError, ReasonCode, TokenError
from pytrat.core.jws import verify_jws
from pytrat.core.keys import KeyProvider, StaticKeySet, VerificationKey
from pytrat.core.scopes import Scope
from pytrat.core.secret import SecretToken
from pytrat.server.errors import OAuthError, OAuthErrorCode
from pytrat.server.forms import parse_json_object
from pytrat.server.workloads import WorkloadIdentity, WorkloadRegistry

__all__ = [
    "JwtAccessTokenValidator",
    "JwtIssuer",
    "SelfSignedValidator",
    "SubjectInfo",
    "SubjectTokenValidator",
    "UnsignedJsonValidator",
]

_MAX_SUBJECT_BYTES: Final = 16_384
_ACCESS_TOKEN_TYP: Final = frozenset({"at+jwt", "jwt"})
_EMPTY: Final[Mapping[str, object]] = MappingProxyType({})
# PyTraT profile: authentication facts copied from a validated subject token into rctx.authn.
_AUTHN_CLAIMS: Final = ("amr", "acr", "auth_time")
# PyTraT profile: a widely used marker for access tokens from the Client Credentials Grant.
_CLIENT_CREDENTIALS_GTY: Final = "client-credentials"


@dataclass(frozen=True, slots=True)
class SubjectInfo:
    """What the TTS learned from a validated subject token.

    Attributes:
        sub: The subject (txn-tokens-11 §11.2.1, §11.2.2: the TTS uses it to determine ``sub``).
        scope: The subject's scope, or ``None`` if it cannot be determined (then issuance is
            refused, txn-tokens-11 §13.14).
        exp: The subject's expiry, if it has one.
        act: The ``act`` claim (RFC 8693 §4.1), if any.
        client_id: The OAuth client the token was issued to, if known.
        authn: Authentication facts (``amr``, ``acr``, ``auth_time``) for ``rctx``.
        client_credentials: True if the token came from a Client Credentials Grant
            (agent-profile-03 §3.2.2).
    """

    sub: str
    scope: Scope | None
    exp: int | None
    act: JsonObject | None = None
    client_id: str | None = None
    authn: Mapping[str, object] = field(default=_EMPTY)
    client_credentials: bool = False


class SubjectTokenValidator(Protocol):
    """Validates one ``subject_token_type``."""

    def validate(self, subject_token: SecretToken, workload: WorkloadIdentity) -> SubjectInfo:
        """Validate ``subject_token`` presented by the authenticated ``workload``.

        Raises:
            OAuthError: ``invalid_grant`` if the token is invalid, expired or untrusted.
        """
        ...


def _invalid_grant(
    description: str, reason: ReasonCode = ReasonCode.SUBJECT_TOKEN_INVALID
) -> OAuthError:
    return OAuthError(OAuthErrorCode.INVALID_GRANT, description, reason)


def _string(payload: Mapping[str, object], name: str, *, required: bool = False) -> str | None:
    value = payload.get(name)
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value:
        raise _invalid_grant(f"subject token claim '{name}' is missing or invalid")
    return value


def _integer(payload: Mapping[str, object], name: str, *, required: bool = False) -> int | None:
    value = payload.get(name)
    if value is None and not required:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise _invalid_grant(f"subject token claim '{name}' is missing or invalid")
    return value


def _scope(payload: Mapping[str, object]) -> Scope | None:
    raw_scope = payload.get("scope")
    if raw_scope is None:
        return None
    if not isinstance(raw_scope, str):
        raise _invalid_grant("subject token scope is invalid")
    try:
        return Scope.parse(raw_scope)
    except TokenError:
        raise _invalid_grant("subject token scope is invalid") from None


def _reject_requester_asserted_act(payload: Mapping[str, object]) -> None:
    """Refuse ``act`` in a subject the requesting workload wrote itself.

    PyTraT profile P28 (security review finding #3): self-signed and unsigned subjects are
    asserted by the requester, so it could otherwise name any registered agent (and inherit its
    assurance) as the delegated actor. Delegation must come from an independent issuer.
    """
    if "act" in payload:
        raise _invalid_grant(
            "a requester-asserted subject may not claim a delegated actor",
            ReasonCode.ISSUANCE_NOT_AUTHORIZED,
        )


def _act(payload: Mapping[str, object]) -> JsonObject | None:
    act = payload.get("act")
    if act is None:
        return None
    if not isinstance(act, Mapping):
        raise _invalid_grant("subject token act claim must be an object")
    return act


def _authn(payload: Mapping[str, object]) -> Mapping[str, object]:
    return MappingProxyType({name: payload[name] for name in _AUTHN_CLAIMS if name in payload})


def _check_not_expired(expires_at: int | None, clock: Clock) -> None:
    # txn-tokens-11 §6: the TTS MUST NOT issue if the presented credential's exp has passed.
    # Deliberately no leeway: the MUST is unconditional.
    if expires_at is not None and clock.now() >= expires_at:
        raise _invalid_grant("subject token has expired", ReasonCode.TOKEN_EXPIRED)


def _audience_matches(aud: object, accepted: frozenset[str]) -> bool:
    if isinstance(aud, str):
        return aud in accepted
    if isinstance(aud, list) and all(isinstance(item, str) for item in aud):
        return bool(accepted.intersection(aud))
    return False


def _verify(
    subject_token: SecretToken,
    keys: KeyProvider,
    algorithms: frozenset[str],
    allowed_typ: frozenset[str] | None,
) -> tuple[Mapping[str, object], VerificationKey]:
    try:
        verified = verify_jws(
            subject_token.reveal(),
            keys,
            algorithms=algorithms,
            allowed_typ=allowed_typ,
            require_kid=True,
            max_bytes=_MAX_SUBJECT_BYTES,
        )
    except TokenError as exc:
        raise _invalid_grant(f"subject token rejected: {exc.detail}", exc.reason) from None
    return verified.payload, verified.key


@dataclass(frozen=True, slots=True)
class JwtIssuer:
    """A trusted access-token issuer."""

    issuer: str
    keys: StaticKeySet
    audience: str
    algorithms: frozenset[str]


class _IssuerKeys:
    """Key provider over every trusted issuer's keys; the ``kid`` identifies the issuer."""

    __slots__ = ("_issuer_by_kid", "_keys")

    def __init__(self, issuers: Iterable[JwtIssuer]) -> None:
        self._keys: dict[str, VerificationKey] = {}
        self._issuer_by_kid: dict[str, JwtIssuer] = {}
        for issuer in issuers:
            for kid in issuer.keys.kids:
                if kid in self._keys:
                    raise ConfigurationError("a kid is shared between subject token issuers")
                key = issuer.keys.get(kid)
                assert key is not None  # noqa: S101 - kid comes from the same set
                self._keys[kid] = key
                self._issuer_by_kid[kid] = issuer

    def get(self, kid: str | None) -> VerificationKey | None:
        return None if kid is None else self._keys.get(kid)

    def issuer_of(self, kid: str) -> JwtIssuer:
        return self._issuer_by_kid[kid]


class JwtAccessTokenValidator:
    """JWT access tokens (RFC 9068 style) from configured issuers.

    The token's ``kid`` selects a trusted key, and with it the issuer whose ``iss``, ``aud`` and
    algorithm allowlist then apply. ``typ`` must be ``at+jwt`` or ``JWT``.
    """

    __slots__ = ("_algorithms", "_clock", "_keys", "_leeway")

    def __init__(
        self, issuers: Iterable[JwtIssuer], *, clock: Clock, leeway_seconds: int = 5
    ) -> None:
        issuer_list = tuple(issuers)
        self._keys = _IssuerKeys(issuer_list)
        self._algorithms = frozenset().union(*(issuer.algorithms for issuer in issuer_list))
        self._clock = clock
        self._leeway = leeway_seconds

    def validate(self, subject_token: SecretToken, workload: WorkloadIdentity) -> SubjectInfo:
        """Validate a JWT access token; see :class:`SubjectTokenValidator`."""
        payload, key = _verify(subject_token, self._keys, self._algorithms, _ACCESS_TOKEN_TYP)
        issuer = self._keys.issuer_of(key.kid)
        if not issuer.algorithms.intersection(key.algorithms):
            raise _invalid_grant("algorithm is not allowed for this issuer")
        if payload.get("iss") != issuer.issuer:
            raise _invalid_grant("subject token issuer is not trusted", ReasonCode.ISSUER_MISMATCH)
        if not _audience_matches(payload.get("aud"), frozenset({issuer.audience})):
            raise _invalid_grant("subject token audience is not accepted")
        # txn-tokens-11 §6: a presented token with an exp MUST NOT be accepted once expired;
        # PyTraT profile: access tokens must carry exp.
        expires_at = _integer(payload, "exp", required=True)
        _check_not_expired(expires_at, self._clock)
        issued_at = _integer(payload, "iat")
        if issued_at is not None and issued_at > self._clock.now() + self._leeway:
            raise _invalid_grant(
                "subject token iat is in the future", ReasonCode.TOKEN_NOT_YET_VALID
            )
        sub = _string(payload, "sub", required=True)
        assert sub is not None  # noqa: S101 - required=True never returns None
        client_id = _string(payload, "client_id")
        return SubjectInfo(
            sub=sub,
            scope=_scope(payload),
            exp=expires_at,
            act=_act(payload),
            client_id=client_id,
            authn=_authn(payload),
            client_credentials=_is_client_credentials(payload, sub, client_id),
        )


def _is_client_credentials(payload: Mapping[str, object], sub: str, client_id: str | None) -> bool:
    # PyTraT profile: a token is treated as client-credentials when it says so (`gty`) or when
    # its subject is the client itself, the RFC 9068 §2.2 convention for that grant.
    return payload.get("gty") == _CLIENT_CREDENTIALS_GTY or (
        client_id is not None and sub == client_id
    )


class SelfSignedValidator:
    """Self-signed JWTs (txn-tokens-11 §11.2.1), verified with the requester's own keys."""

    __slots__ = ("_algorithms", "_clock", "_leeway", "_max_age", "_registry", "_tts_ids")

    def __init__(
        self,
        registry: WorkloadRegistry,
        *,
        tts_identifiers: frozenset[str],
        algorithms: frozenset[str],
        clock: Clock,
        leeway_seconds: int = 5,
        max_age_seconds: int = 300,
    ) -> None:
        self._registry = registry
        self._tts_ids = tts_identifiers
        self._algorithms = algorithms
        self._clock = clock
        self._leeway = leeway_seconds
        self._max_age = max_age_seconds

    def validate(self, subject_token: SecretToken, workload: WorkloadIdentity) -> SubjectInfo:
        """Validate a self-signed JWT; see :class:`SubjectTokenValidator`."""
        keys = self._registry.keys_for(workload.id)
        if keys is None:
            raise _invalid_grant("requesting workload has no registered keys")
        payload, _ = _verify(subject_token, keys, self._algorithms, None)
        # txn-tokens-11 §11.2.1: iss is "the unique identifier of the requesting workload".
        if payload.get("iss") != workload.id:
            raise _invalid_grant("self-signed iss must be the requesting workload")
        # txn-tokens-11 §11.2.1: "The TTS SHALL verify that [aud] matches its own identifier".
        if not _audience_matches(payload.get("aud"), self._tts_ids):
            raise _invalid_grant("self-signed aud is not this TTS")
        issued_at = _integer(payload, "iat", required=True)
        expires_at = _integer(payload, "exp", required=True)
        assert issued_at is not None  # noqa: S101 - required=True never returns None
        now = self._clock.now()
        # txn-tokens-11 §11.2.1: the TTS may reject an iat unreasonably far in the past or future.
        if issued_at > now + self._leeway:
            raise _invalid_grant("self-signed iat is in the future", ReasonCode.TOKEN_NOT_YET_VALID)
        if issued_at < now - self._max_age:
            raise _invalid_grant("self-signed token is too old", ReasonCode.TOKEN_EXPIRED)
        _check_not_expired(expires_at, self._clock)
        sub = _string(payload, "sub", required=True)
        assert sub is not None  # noqa: S101 - required=True never returns None
        _reject_requester_asserted_act(payload)
        return SubjectInfo(sub=sub, scope=_scope(payload), exp=expires_at)


class UnsignedJsonValidator:
    """Unsigned JSON subjects (txn-tokens-11 §11.2.2).

    Disabled for every workload not explicitly listed: an unsigned subject is only as
    trustworthy as the workload asserting it.
    """

    __slots__ = ("_allowed", "_clock")

    def __init__(self, allowed_workloads: frozenset[str], *, clock: Clock) -> None:
        self._allowed = allowed_workloads
        self._clock = clock

    def validate(self, subject_token: SecretToken, workload: WorkloadIdentity) -> SubjectInfo:
        """Parse an unsigned JSON subject; see :class:`SubjectTokenValidator`."""
        if workload.id not in self._allowed:
            raise OAuthError(
                OAuthErrorCode.UNAUTHORIZED_CLIENT,
                "workload may not use unsigned_json subject tokens",
                ReasonCode.ISSUANCE_NOT_AUTHORIZED,
            )
        raw = subject_token.reveal()
        if len(raw) > _MAX_SUBJECT_BYTES:
            raise _invalid_grant("subject token is too large", ReasonCode.TOKEN_MALFORMED)
        try:
            payload = parse_json_object(raw)
        except ValueError:
            raise _invalid_grant(
                "subject token is not a JSON object", ReasonCode.TOKEN_MALFORMED
            ) from None
        # txn-tokens-11 §11.2.2: sub is REQUIRED.
        sub = _string(payload, "sub", required=True)
        assert sub is not None  # noqa: S101 - required=True never returns None
        expires_at = _integer(payload, "exp")
        _check_not_expired(expires_at, self._clock)
        _reject_requester_asserted_act(payload)
        return SubjectInfo(sub=sub, scope=_scope(payload), exp=expires_at)
