# pytrat-client

The outbound half of PyTraT (OAuth Transaction Tokens): RFC 8693 token exchange
with the Transaction Token Service, workload credentials (RFC 7523 `private_key_jwt`, mTLS, SPIFFE
JWT-SVID), a propagating HTTP client and JWKS refresh. Sync and async variants of everything.
Depends only on `pytrat-core` and `httpx`.

```bash
pip install pytrat-client
```

## Obtain a token and forward it

```python
from pytrat.client import (
    AsyncTransactionClient, AsyncTransactionTokenClient, PrivateKeyJwtCredential, bind_transaction,
)
from pytrat.core.constants import TOKEN_TYPE_ACCESS_TOKEN

endpoint = "https://tts.payments.internal/token"
tts = AsyncTransactionTokenClient(
    endpoint,
    PrivateKeyJwtCredential("api-gateway", "keys/api-gateway.pem", alg="ES256",
                            kid="api-gateway", token_endpoint=endpoint),
    verifier,  # a pytrat.core.TokenVerifier trusting the TTS's keys
)
payments = AsyncTransactionClient(["https://payment.payments.internal"])  # exact-origin allowlist

token = await tts.issue(audience="payments.internal", scope="payments.transfer",
                        subject_token=access_token, subject_token_type=TOKEN_TYPE_ACCESS_TOKEN,
                        request_details=transfer)  # verified locally before it is returned
with bind_transaction(token):
    await payments.post("https://payment.payments.internal/internal/payments", json=transfer)
```

The token is sent only in the `Txn-Token` header, only to allowlisted HTTPS origins (checked before
connecting), and redirects are never followed. `replace()` refuses to widen scope and rejects a TTS
reply that changed an immutable claim.

## Documentation

PyTraT documentation: *Client and propagation* and the `pytrat.client` API reference (sources in
`docs/` of the repository).

Apache-2.0.
