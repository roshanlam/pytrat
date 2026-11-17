# pytrat-core

Transaction Token models, verification, scopes, context binding, workload authentication and audit
events for PyTraT, a Python implementation of OAuth Transaction Tokens
(`draft-ietf-oauth-transaction-tokens-11`).

No web framework, HTTP client or agent dependency: only PyJWT (with `cryptography`) and Pydantic.
Use it directly to verify Txn-Tokens in any framework, or through `pytrat-fastapi` /
`pytrat-django`.

```bash
pip install pytrat-core
```

## Verify a token and bind the request to it

```python
from pytrat.core import ContextBinding, StaticKeySet, TokenVerifier, VerifierSettings

verifier = TokenVerifier(
    VerifierSettings(trust_domain="payments.internal", algorithms=frozenset({"ES256"})),
    StaticKeySet.from_jwks_file("tts.jwks.json"),  # trusted keys from configuration only
)
binding = ContextBinding.compile(["source_account", "amount_minor", "currency"])

verified = verifier.verify(raw_token)  # raises TokenError with a specific ReasonCode
binding.check(verified.claims.tctx, request_body)  # strict: "10000" != 10000, floats refused
```

`verify` returns a `VerifiedToken` (which cannot be constructed any other way) or raises. `none`
and `HS*` can never be enabled, keys are never taken from the token (`jwk`, `jku`, `x5u`, `x5c` are
rejected), and tokens are wrapped in `SecretToken` so they never reach logs or exceptions.

Test helpers that mint tokens live in `pytrat.core.testing` (`TokenFactory`, `generate_test_key`)
and must never be imported by production code.

## Documentation

PyTraT documentation: *Concepts*, *Errors and reason codes*, and the `pytrat.core` API reference
(sources in `docs/` of the repository; build with `uv run --group docs mkdocs serve`).

Apache-2.0.
