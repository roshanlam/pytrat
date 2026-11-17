"""MkDocs hook: generate reference tables from the code so the documentation cannot drift.

``<!-- pytrat:reason-codes -->`` in a page is replaced by a table built from
:class:`pytrat.core.ReasonCode`, in enum order. Every code needs an entry in :data:`REASON_CODES`;
a code without one (or an entry for a code that does not exist) fails the build, and
``tests/docs/test_docs_drift.py`` checks the same thing in the normal test run.
"""

from __future__ import annotations

import re
from typing import Final, NamedTuple

from pytrat.core import ReasonCode

REASON_CODES_MARKER: Final = "<!-- pytrat:reason-codes -->"


class ReasonDoc(NamedTuple):
    """How one reason code surfaces and what it means."""

    status: str
    raised_by: str
    meaning: str


_TOKEN = "`TokenError`"
_AUTHN = "`AuthenticationError`"
_AUTHZ = "`AuthorizationError`"

#: Documentation for every :class:`ReasonCode`. Statuses are those of the resource-side error
#: classes; at the TTS the same codes are recorded in the audit log and returned as RFC 6749
#: errors (see the "Token endpoint" section of the errors guide).
REASON_CODES: Final[dict[ReasonCode, ReasonDoc]] = {
    ReasonCode.TOKEN_MISSING: ReasonDoc(
        "401", _TOKEN, "No `Txn-Token` header, or no transaction is bound for an outbound call."
    ),
    ReasonCode.TOKEN_MALFORMED: ReasonDoc(
        "401",
        _TOKEN,
        "Not a compact JWS, oversized, undecodable, duplicate JSON members, or the header "
        "was sent more than once.",
    ),
    ReasonCode.TOKEN_TYPE_INVALID: ReasonDoc(
        "401", _TOKEN, "JOSE `typ` is not `txntoken+jwt` (or the expected type for the input)."
    ),
    ReasonCode.ALGORITHM_NOT_ALLOWED: ReasonDoc(
        "401",
        _TOKEN,
        "`alg` is not on the allowlist, is `none`/`HS*`, or does not fit the key type; or a "
        "forbidden header (`jwk`, `jku`, `x5u`, `x5c`, `crit`, `b64`) is present.",
    ),
    ReasonCode.KEY_UNKNOWN: ReasonDoc(
        "401", _TOKEN, "`kid` is missing (when required) or not among the trusted keys."
    ),
    ReasonCode.SIGNATURE_INVALID: ReasonDoc(
        "401", _TOKEN, "The signature does not verify with the trusted key."
    ),
    ReasonCode.CLAIM_MISSING: ReasonDoc("401", _TOKEN, "A required claim is absent."),
    ReasonCode.CLAIM_INVALID: ReasonDoc(
        "401",
        _TOKEN,
        "A claim has the wrong type or shape (including an array `aud`, or a float in a bound "
        "`tctx` value).",
    ),
    ReasonCode.TOKEN_EXPIRED: ReasonDoc("401", _TOKEN, "`exp` has passed (beyond the leeway)."),
    ReasonCode.TOKEN_NOT_YET_VALID: ReasonDoc(
        "401", _TOKEN, "`iat` is in the future (beyond the leeway)."
    ),
    ReasonCode.LIFETIME_EXCEEDED: ReasonDoc(
        "401", _TOKEN, "`exp - iat` exceeds the verifier's `max_lifetime` (default 300 s)."
    ),
    ReasonCode.TRUST_DOMAIN_MISMATCH: ReasonDoc(
        "401", _TOKEN, "`aud` is not this verifier's Trust Domain."
    ),
    ReasonCode.ISSUER_MISMATCH: ReasonDoc(
        "401", _TOKEN, "`iss` is absent or differs from `expected_issuer`."
    ),
    ReasonCode.SCOPE_INSUFFICIENT: ReasonDoc(
        "403", _AUTHZ, "The token's scope contains none of the route's allowed scopes."
    ),
    ReasonCode.TRANSACTION_CONTEXT_MISSING: ReasonDoc(
        "403", _AUTHZ, "The token has no `tctx`, or no value at a bound `tctx` path."
    ),
    ReasonCode.TRANSACTION_CONTEXT_MISMATCH: ReasonDoc(
        "403",
        _AUTHZ,
        "A bound request value is absent, unbindable or differs (strictly) from `tctx`.",
    ),
    ReasonCode.CALLER_NOT_ALLOWED: ReasonDoc(
        "403", _AUTHZ, "The authenticated caller is not in `allowed_callers`."
    ),
    ReasonCode.WORKLOAD_UNAUTHENTICATED: ReasonDoc(
        "401", _AUTHN, "No valid workload credential, while the route requires one."
    ),
    ReasonCode.REPLAY_DETECTED: ReasonDoc(
        "403",
        _AUTHZ,
        "A `single_use` route saw the same `txn` again, or a client assertion `jti` was reused.",
    ),
    ReasonCode.POLICY_NOT_FOUND: ReasonDoc(
        "403",
        _AUTHZ,
        "No policy for the route (default deny), or a route under a protected prefix is "
        "unguarded. Also raised at startup by route-coverage checks.",
    ),
    ReasonCode.POLICY_INVALID: ReasonDoc(
        "500 (startup)", "`ConfigurationError`", "A policy or setting is invalid."
    ),
    ReasonCode.DEPENDENCY_UNAVAILABLE: ReasonDoc(
        "503",
        "`DependencyError`",
        "A store, directory or key source needed for the decision is unavailable: deny.",
    ),
    ReasonCode.AGENT_UNVERIFIED: ReasonDoc(
        "403", _AUTHZ, "An agent in the chain is not registered in the trusted store."
    ),
    ReasonCode.AGENT_HOP_LIMIT_EXCEEDED: ReasonDoc(
        "403", _AUTHZ, "`chain_metadata.hop_count` exceeds the limit."
    ),
    ReasonCode.AGENT_ASSURANCE_INSUFFICIENT: ReasonDoc(
        "403", _AUTHZ, "The chain's minimum assurance is below the required level, or unknown."
    ),
    ReasonCode.AGENT_NOT_ALLOWED: ReasonDoc(
        "403", _AUTHZ, "The originating agent is not in `allowed_originators`."
    ),
    ReasonCode.AGENT_CONTEXT_MISSING: ReasonDoc(
        "403", _AUTHZ, "An agent constraint applies but the token carries no `agentic_ctx`."
    ),
    ReasonCode.REPLACEMENT_WIDENS_AUTHORIZATION: ReasonDoc(
        "403",
        _AUTHZ,
        "A replacement would widen scope, change an immutable claim or lower `hop_count`.",
    ),
    ReasonCode.REPLACEMENT_LIMIT_EXCEEDED: ReasonDoc(
        "TTS 400 `invalid_grant`",
        "`OAuthError`",
        "`max_replacements_per_txn` reached for a lifetime-extending replacement.",
    ),
    ReasonCode.DESTINATION_NOT_TRUSTED: ReasonDoc(
        "client-side",
        _AUTHZ,
        "An outbound request targets an origin outside the propagation allowlist.",
    ),
    ReasonCode.EXCHANGE_FAILED: ReasonDoc(
        "502",
        "`ExchangeError`",
        "The TTS refused the exchange or returned a non-conforming response.",
    ),
    ReasonCode.SUBJECT_TOKEN_INVALID: ReasonDoc(
        "401",
        f"{_AUTHN}, `ExchangeError`, `OAuthError`",
        "The subject token is absent, of a refused type, or failed validation.",
    ),
    ReasonCode.ISSUANCE_NOT_AUTHORIZED: ReasonDoc(
        "TTS 400 `unauthorized_client`",
        "`OAuthError`",
        "The TTS issuance policy does not allow this workload, subject or agent.",
    ),
    ReasonCode.RATE_LIMITED: ReasonDoc(
        "TTS 429 `slow_down`", "`OAuthError`", "The authenticated workload exceeded its budget."
    ),
    ReasonCode.TOOL_ARGUMENTS_INVALID: ReasonDoc(
        "400", "`ToolArgumentError`", "Model-supplied tool arguments failed strict validation."
    ),
    ReasonCode.TOOL_RESULT_BLOCKED: ReasonDoc(
        "500",
        "`ToolResultBlockedError`",
        "A tool result contained a token-shaped string or an unscannable value.",
    ),
    ReasonCode.REQUEST_MALFORMED: ReasonDoc(
        "400 / 415 / 422",
        "`RequestError`",
        "The request's own data to be bound is malformed or ambiguous.",
    ),
}


def check_reason_codes() -> None:
    """Fail unless :data:`REASON_CODES` documents exactly the members of :class:`ReasonCode`.

    Raises:
        ValueError: Naming the undocumented or unknown codes.
    """
    missing = [code.value for code in ReasonCode if code not in REASON_CODES]
    unknown = [code.value for code in REASON_CODES if code not in set(ReasonCode)]
    if missing or unknown:
        raise ValueError(f"reason-code docs out of date: missing={missing} unknown={unknown}")


def reason_code_table() -> str:
    """Render the reason-code reference table as Markdown, in enum order."""
    check_reason_codes()
    rows = [
        "| Reason code | HTTP status | Raised as | Meaning |",
        "|---|---|---|---|",
    ]
    for code in ReasonCode:
        doc = REASON_CODES[code]
        rows.append(f"| `{code.value}` | {doc.status} | {doc.raised_by} | {doc.meaning} |")
    return "\n".join(rows)


def on_page_markdown(markdown: str, **_: object) -> str:
    """MkDocs event: expand generated tables."""
    if REASON_CODES_MARKER in markdown:
        markdown = markdown.replace(REASON_CODES_MARKER, reason_code_table())
    return markdown


# Docstrings use Sphinx cross-reference roles (:class:`~pytrat.core.StaticKeySet`), which Markdown
# renders as ':class:' followed by inline code. Turn them into cross-references (fully qualified
# targets) or plain inline code (everything else).
_ROLE = re.compile(r":(?:class|func|meth|attr|mod|data|exc|obj):<code>([^<]*)</code>")
_EXPLICIT_TARGET = re.compile(r"^(?P<text>.*?)\s*&lt;(?P<target>[^&]+)&gt;$")


def _resolve_role(match: re.Match[str]) -> str:
    inner = match[1]
    explicit = _EXPLICIT_TARGET.match(inner)
    if explicit:
        text, target = explicit["text"], explicit["target"]
    else:
        target = inner.lstrip("~")
        text = target.rsplit(".", 1)[-1] if inner.startswith("~") else target
    if target.startswith("pytrat."):
        return f'<autoref identifier="{target}" optional><code>{text}</code></autoref>'
    return f"<code>{text}</code>"


def on_page_content(html: str, **_: object) -> str:
    """MkDocs event: render Sphinx roles left in docstrings."""
    return _ROLE.sub(_resolve_role, html)
