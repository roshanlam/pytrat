from collections.abc import Mapping
from pathlib import Path

import httpx

from pytrat.client import (
    AsyncJwksRefresher,
    AsyncTransactionClient,
    AsyncTransactionTokenClient,
    PrivateKeyJwtCredential,
    WorkloadJwtAuth,
    bind_transaction,
)
from pytrat.core import Scope, SecretToken, TokenVerifier, VerifiedToken, VerifierSettings
from pytrat.core.constants import TOKEN_TYPE_ACCESS_TOKEN

TRUST_DOMAIN = "payments.internal"
TTS = "https://tts.payments.internal"
TOKEN_ENDPOINT = f"{TTS}/token"
PAYMENTS = "https://payment.payments.internal"


# --8<-- [start:verifier]
def tts_verifier(http: httpx.AsyncClient | None = None) -> tuple[TokenVerifier, AsyncJwksRefresher]:
    # The JWKS URL is pinned in configuration; the token can never point at its own key.
    jwks = AsyncJwksRefresher(f"{TTS}/.well-known/jwks.json", http_client=http)
    settings = VerifierSettings(
        trust_domain=TRUST_DOMAIN, expected_issuer=TTS, algorithms=frozenset({"ES256"})
    )
    return TokenVerifier(settings, jwks.keys), jwks


# --8<-- [end:verifier]


# --8<-- [start:exchange]
def tts_client(
    verifier: TokenVerifier, private_key: Path, http: httpx.AsyncClient | None = None
) -> AsyncTransactionTokenClient:
    credential = PrivateKeyJwtCredential(  # RFC 7523: a fresh signed assertion per request
        "api-gateway",
        private_key,
        alg="ES256",
        kid="api-gateway",
        token_endpoint=TOKEN_ENDPOINT,
    )
    return AsyncTransactionTokenClient(TOKEN_ENDPOINT, credential, verifier, http_client=http)


async def start_transfer(
    tts: AsyncTransactionTokenClient, access_token: SecretToken, transfer: Mapping[str, object]
) -> VerifiedToken:
    # The returned token has already been verified locally against the trusted keys.
    return await tts.issue(
        audience=TRUST_DOMAIN,
        scope="payments.transfer payments.read",  # granted: requested ∩ policy ∩ subject scope
        subject_token=access_token,
        subject_token_type=TOKEN_TYPE_ACCESS_TOKEN,
        request_details=transfer,  # becomes tctx, filtered by the TTS issuance policy
        request_context={"req_ip": "203.0.113.7"},  # becomes rctx
    )


# --8<-- [end:exchange]


# --8<-- [start:replace]
async def narrow_to_read_only(
    tts: AsyncTransactionTokenClient, current: VerifiedToken
) -> VerifiedToken:
    # Raises REPLACEMENT_WIDENS_AUTHORIZATION before any I/O if the scope would widen, and again
    # if the TTS reply changed txn, sub, aud, act or the agent originator.
    return await tts.replace(current, Scope.parse("payments.read"))


# --8<-- [end:replace]


# --8<-- [start:propagate]
def payments_client(
    private_key: Path, http: httpx.AsyncClient | None = None
) -> AsyncTransactionClient:
    return AsyncTransactionClient(
        [PAYMENTS],  # exact origins the token may be sent to; redirects are never followed
        http_client=http,
        auth=WorkloadJwtAuth(  # authenticates this workload to the destination
            workload_id="api-gateway",
            private_key_path=private_key,
            kid="api-gateway",
            alg="ES256",
            audiences={PAYMENTS: "payment-service"},
        ),
    )


async def forward_transfer(
    payments: AsyncTransactionClient, token: VerifiedToken, transfer: Mapping[str, object]
) -> httpx.Response:
    # Inside a PyTraT-protected handler the token is already bound; elsewhere, bind it yourself.
    with bind_transaction(token):
        return await payments.post(f"{PAYMENTS}/internal/payments", json=dict(transfer))


# --8<-- [end:propagate]
