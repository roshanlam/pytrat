"""Tokenetes interoperability against a running Tokenetes stack (``-m interop``).

Skipped unless ``PYTRAT_TOKENETES_URL`` points at the control API of the stack started by
``tests/interoperability/docker/docker-compose.yml`` (real Tokenetes and tokenetes-agent binaries,
real SPIRE, a mock tconfigd). See ``docs/interop/tokenetes.md`` for how to run it.

Environment:
    PYTRAT_TOKENETES_URL             mock tconfigd control API, e.g. http://127.0.0.1:18080
    PYTRAT_TOKENETES_TOKEN_ENDPOINT  default https://127.0.0.1:18443/token_endpoint
    PYTRAT_TOKENETES_AGENT_URL       default http://127.0.0.1:19030
    PYTRAT_TOKENETES_SVID_DIR        default tests/interoperability/docker/.run
"""

from __future__ import annotations

import base64
import json
import os
import ssl
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from pytrat.core import (
    ReasonCode,
    StaticKeySet,
    SystemClock,
    TokenError,
    TokenVerifier,
    VerifierSettings,
)
from pytrat.core.constants import (
    EXCHANGE_RESPONSE_TOKEN_TYPE,
    GRANT_TYPE_TOKEN_EXCHANGE,
    TOKEN_TYPE_ACCESS_TOKEN,
    TOKEN_TYPE_SELF_SIGNED,
    TOKEN_TYPE_TXN_TOKEN,
    TXN_TOKEN_HEADER,
)
from pytrat.core.jws import verify_jws
from pytrat.core.testing import FrozenClock, TokenFactory, b64url, generate_test_key
from pytrat.server import KeyRingSigner, SigningKey

CONTROL_URL = os.environ.get("PYTRAT_TOKENETES_URL")

pytestmark = [
    pytest.mark.interop,
    pytest.mark.skipif(not CONTROL_URL, reason="PYTRAT_TOKENETES_URL not set (no Tokenetes stack)"),
]

TOKEN_ENDPOINT = os.environ.get(
    "PYTRAT_TOKENETES_TOKEN_ENDPOINT", "https://127.0.0.1:18443/token_endpoint"
)
AGENT_URL = os.environ.get("PYTRAT_TOKENETES_AGENT_URL", "http://127.0.0.1:19030")
SVID_DIR = Path(
    os.environ.get("PYTRAT_TOKENETES_SVID_DIR", Path(__file__).parent / "docker" / ".run")
)
VECTORS = json.loads((Path(__file__).parent / "vectors" / "tokenetes.json").read_text())

# Must match tests/interoperability/docker/rules/*.json.
ISSUER = "https://alphastocks.example/tokenetes"
AUDIENCE = "https://alphastocks.example/"
ORDER = {"stockId": 7, "orderType": "BUY", "quantity": 5}
REQUEST_CONTEXT = {"req_ip": "203.0.113.7"}


def _b64json(value: object) -> str:
    return b64url(json.dumps(value).encode())


def _segment(token: str, index: int) -> dict[str, object]:
    raw = token.split(".")[index]
    decoded: dict[str, object] = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    return decoded


def _gateway_tls() -> ssl.SSLContext:
    """Client TLS as the SPIFFE workload spiffe://interop.test/gateway.

    The server presents an X.509-SVID with only a SPIFFE URI SAN, so hostname checking is off; the
    chain is still verified against the SPIRE trust bundle.
    """
    context = ssl.create_default_context(cafile=str(SVID_DIR / "bundle.0.pem"))
    context.check_hostname = False
    context.load_cert_chain(SVID_DIR / "svid.0.pem", SVID_DIR / "svid.0.key")
    return context


def _subject_token() -> str:
    # The stack configures Tokenetes with selfSigned.validation=false, so the subject token is only
    # parsed. Its `sub` is an RFC 9493 email identifier, as Tokenetes produces for OIDC subjects.
    claims = {"sub": {"format": "email", "email": "alice@example.com"}}
    return f"{_b64json({'alg': 'none', 'typ': 'JWT'})}.{_b64json(claims)}."


def _tokenetes_form(**overrides: str) -> dict[str, str]:
    details = {"path": "/api/order", "method": "POST", "body": ORDER}
    form = {
        "grant_type": GRANT_TYPE_TOKEN_EXCHANGE,
        "requested_token_type": TOKEN_TYPE_TXN_TOKEN,
        "audience": AUDIENCE,
        "subject_token": _subject_token(),
        "subject_token_type": TOKEN_TYPE_SELF_SIGNED,
        "request_details": _b64json({**details, "headers": {}, "queryParameters": {}}),
        "request_context": _b64json(REQUEST_CONTEXT),
    }
    return {**form, **overrides}


@pytest.fixture(scope="module")
def tokenetes() -> Iterator[httpx.Client]:
    with httpx.Client(verify=_gateway_tls(), timeout=10) as client:
        yield client


@pytest.fixture(scope="module")
def tokenetes_keys() -> StaticKeySet:
    response = httpx.get(f"{CONTROL_URL}/tokenetes-jwks", timeout=20)
    response.raise_for_status()
    return StaticKeySet.from_jwks_bytes(response.content)


@pytest.fixture
def issued(tokenetes: httpx.Client) -> dict[str, object]:
    response = tokenetes.post(TOKEN_ENDPOINT, data=_tokenetes_form())
    assert response.status_code == 200
    document: dict[str, object] = response.json()
    return document


@pytest.fixture
def agent_trusts_extra_keys() -> Iterator[httpx.Client]:
    with httpx.Client(timeout=20) as client:
        yield client
        client.put(f"{CONTROL_URL}/extra-jwks", json={"keys": []}).raise_for_status()


def _agent_verify(client: httpx.Client, token: str) -> httpx.Response:
    return client.post(
        f"{AGENT_URL}/verify-trat",
        json={
            "path": "/api/order",
            "method": "POST",
            "headers": {TXN_TOKEN_HEADER: token},
            "queryParameters": {},
            "body": ORDER,
        },
    )


def _pytrat_signed(alg: str, claims: dict[str, object]) -> tuple[str, dict[str, object]]:
    """Sign with the reference TTS's own signer (typ txntoken+jwt)."""
    # A fresh kid each time: tokenetes-agent caches keys by kid and refetches only on a miss.
    key = generate_test_key(alg)
    signer = KeyRingSigner([SigningKey(kid=key.kid, alg=alg, private_key=key.private_key)])
    return signer.sign(claims), signer.jwks()


def _draft_11_claims() -> dict[str, object]:
    # The claim set the PyTraT TTS issues, with Tokenetes' iss/aud so only the format differs.
    factory = TokenFactory(key=generate_test_key(), clock=FrozenClock(SystemClock().now()))
    return factory.claims(iss=ISSUER, aud=AUDIENCE, scope="stock-trade", tctx=ORDER)


# Tokenetes as TTS.


def test_tokenetes_issues_with_draft_11_response_members(issued: dict[str, object]) -> None:
    """txn-tokens-11 §11.4: token_type N_A, issued_token_type the txn_token URN."""
    assert issued["token_type"] == EXCHANGE_RESPONSE_TOKEN_TYPE
    assert issued["issued_token_type"] == TOKEN_TYPE_TXN_TOKEN
    assert isinstance(issued["access_token"], str)


def test_live_tokenetes_token_matches_the_fixture_shape(
    issued: dict[str, object], tokenetes_keys: StaticKeySet
) -> None:
    """Guards the fixture suite against drift: verify Tokenetes' signature, then compare shapes."""
    token = str(issued["access_token"])
    verified = verify_jws(
        token, tokenetes_keys, algorithms=frozenset({"RS256"}), allowed_typ=frozenset({"txn_token"})
    )

    expected = VECTORS["token"]
    assert sorted(_segment(token, 0)) == sorted(expected["header"])
    assert _segment(token, 0)["typ"] == expected["header"]["typ"]
    assert sorted(verified.payload) == sorted(expected["claims"])
    assert verified.payload["sub"] == {"format": "email", "email": "alice@example.com"}
    assert verified.payload["purp"] == "stock-trade"
    assert verified.payload["azd"] == {"stockId": 7, "action": "BUY", "quantity": 5}
    assert verified.payload["rctx"] == REQUEST_CONTEXT
    assert verified.payload["aud"] == AUDIENCE


def test_pytrat_verifier_rejects_live_tokenetes_token(
    issued: dict[str, object], tokenetes_keys: StaticKeySet
) -> None:
    """txn-tokens-11 §9.1: Tokenetes' typ txn_token is rejected even with its keys trusted."""
    verifier = TokenVerifier(
        VerifierSettings(
            trust_domain=AUDIENCE, algorithms=frozenset({"RS256"}), expected_issuer=ISSUER
        ),
        tokenetes_keys,
    )

    with pytest.raises(TokenError) as excinfo:
        verifier.verify(str(issued["access_token"]))

    assert excinfo.value.reason is ReasonCode.TOKEN_TYPE_INVALID


def test_tokenetes_rejects_draft_11_style_token_request(tokenetes: httpx.Client) -> None:
    """A -11 §11.1 request (access_token subject, JSON request_details, scope) is refused."""
    form = _tokenetes_form(
        subject_token_type=TOKEN_TYPE_ACCESS_TOKEN,
        scope="stock-trade",
        request_details=json.dumps({"path": "/api/order", "method": "POST"}),
        request_context=json.dumps(REQUEST_CONTEXT),
    )

    response = tokenetes.post(TOKEN_ENDPOINT, data=form)

    # handler.go: subject_token_type other than id_token/self_signed -> 422.
    assert response.status_code == 422


def test_tokenetes_rejects_unencoded_request_details(tokenetes: httpx.Client) -> None:
    """-11 §11.1 sends request_details as JSON (since -07); Tokenetes requires base64url."""
    form = _tokenetes_form(request_details=json.dumps({"path": "/api/order", "method": "POST"}))

    response = tokenetes.post(TOKEN_ENDPOINT, data=form)

    assert response.status_code == 400


def test_tokenetes_token_endpoint_requires_spiffe_mtls() -> None:
    """Workload authentication is SPIFFE mTLS only; no client certificate, no connection."""
    context = ssl.create_default_context(cafile=str(SVID_DIR / "bundle.0.pem"))
    context.check_hostname = False

    with httpx.Client(verify=context, timeout=10) as client, pytest.raises(httpx.TransportError):
        client.post(TOKEN_ENDPOINT, data=_tokenetes_form())


# tokenetes-agent as verifier.


def test_tokenetes_agent_accepts_tokenetes_token(issued: dict[str, object]) -> None:
    """Control: the stack's agent verifies Tokenetes' own token."""
    with httpx.Client(timeout=20) as client:
        response = _agent_verify(client, str(issued["access_token"]))

    assert response.status_code == 200
    assert response.json() == {"valid": True, "reason": ""}


def test_tokenetes_agent_cannot_verify_pytrat_tts_token(
    agent_trusts_extra_keys: httpx.Client,
) -> None:
    """An RS256 -11 token with the agent trusting its key: ``sub`` (a string) fails to decode."""
    token, jwks = _pytrat_signed("RS256", _draft_11_claims())
    agent_trusts_extra_keys.put(f"{CONTROL_URL}/extra-jwks", json=jwks).raise_for_status()

    response = _agent_verify(agent_trusts_extra_keys, token)

    # tratverifier.go returns the claims-decoding error; handler.go maps it to 500.
    assert response.status_code == 500


def test_tokenetes_agent_rejects_pytrat_default_es256_token(
    agent_trusts_extra_keys: httpx.Client,
) -> None:
    """The PyTraT TTS default ES256 is outside the agent's RSA-only check."""
    claims = _draft_11_claims()
    claims["sub"] = {"format": "email", "email": "alice@example.com"}
    claims["purp"] = "stock-trade"
    token, jwks = _pytrat_signed("ES256", claims)
    agent_trusts_extra_keys.put(f"{CONTROL_URL}/extra-jwks", json=jwks).raise_for_status()

    response = _agent_verify(agent_trusts_extra_keys, token)

    assert response.status_code == 500


def test_tokenetes_agent_accepts_pytrat_signature_in_tokenetes_vocabulary(
    agent_trusts_extra_keys: httpx.Client,
) -> None:
    """Diagnostic, not a supported flow: the blockers are claim vocabulary, not crypto or typ.

    Signed by PyTraT's TTS signer (RS256, typ txntoken+jwt) but carrying Tokenetes' claims, the
    agent accepts it. The PyTraT TTS never issues this shape.
    """
    claims = _draft_11_claims()
    claims["sub"] = {"format": "email", "email": "alice@example.com"}
    claims["purp"] = "stock-trade"
    claims["azd"] = {"stockId": 7, "action": "BUY", "quantity": 5}
    token, jwks = _pytrat_signed("RS256", claims)
    agent_trusts_extra_keys.put(f"{CONTROL_URL}/extra-jwks", json=jwks).raise_for_status()

    response = _agent_verify(agent_trusts_extra_keys, token)

    assert response.status_code == 200
    assert response.json() == {"valid": True, "reason": ""}
