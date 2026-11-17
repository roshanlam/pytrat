"""Protocol constants.

Every protocol string PyTraT uses is defined here, so a draft revision that renames one is a
one-line change.
"""

from __future__ import annotations

from typing import Final

#: Specification revisions this release implements. Conformance is claimed only for these.
SUPPORTED_DRAFTS: Final = {
    "transaction-tokens": "draft-ietf-oauth-transaction-tokens-11",
    "agent-profile": "draft-araut-oauth-transaction-tokens-for-agents-03",
}

# txn-tokens-11 §9.1: the JOSE header `typ` MUST be `txntoken+jwt`.
TXN_TOKEN_TYP: Final = "txntoken+jwt"

# txn-tokens-11 §12.1: Txn-Tokens are carried in this HTTP header, never in `Authorization`.
TXN_TOKEN_HEADER: Final = "Txn-Token"

# txn-tokens-11 §11.1 / RFC 8693 §2.1.
GRANT_TYPE_TOKEN_EXCHANGE: Final = "urn:ietf:params:oauth:grant-type:token-exchange"
TOKEN_TYPE_TXN_TOKEN: Final = "urn:ietf:params:oauth:token-type:txn_token"
TOKEN_TYPE_ACCESS_TOKEN: Final = "urn:ietf:params:oauth:token-type:access_token"
TOKEN_TYPE_REFRESH_TOKEN: Final = "urn:ietf:params:oauth:token-type:refresh_token"
TOKEN_TYPE_ID_TOKEN: Final = "urn:ietf:params:oauth:token-type:id_token"
TOKEN_TYPE_JWT: Final = "urn:ietf:params:oauth:token-type:jwt"
# txn-tokens-11 §11.2.1 and §11.2.2.
TOKEN_TYPE_SELF_SIGNED: Final = "urn:ietf:params:oauth:token-type:self_signed"
TOKEN_TYPE_UNSIGNED_JSON: Final = "urn:ietf:params:oauth:token-type:unsigned_json"

# txn-tokens-11 §11.4: the exchange response `token_type` MUST be "N_A".
EXCHANGE_RESPONSE_TOKEN_TYPE: Final = "N_A"

# RFC 7523 client assertion type for private_key_jwt workload authentication.
CLIENT_ASSERTION_TYPE_JWT_BEARER: Final = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

# PyTraT profile: algorithms that can never be enabled. `none` is unsigned; HMAC algorithms would
# require every verifier to hold the signing secret, defeating "only the TTS signs".
FORBIDDEN_ALGORITHMS: Final = frozenset({"none", "HS256", "HS384", "HS512"})

# PyTraT profile: algorithms the verifier knows how to bind to key types.
SUPPORTED_ALGORITHMS: Final = frozenset(
    {"ES256", "ES384", "ES512", "EdDSA", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512"}
)

# PyTraT profile: secure defaults. RS256 is opt-in for interoperability.
DEFAULT_ALGORITHMS: Final = frozenset({"ES256", "EdDSA", "PS256"})

# PyTraT profile: JOSE header parameters that would let a token choose its own key, or that
# change processing in ways this verifier does not implement.
FORBIDDEN_HEADER_PARAMETERS: Final = frozenset({"jwk", "jku", "x5u", "x5c", "crit", "b64"})
