"""Workload credentials (txn-tokens-11 §11.5)."""

from __future__ import annotations

import base64
import datetime as dt
import json
import ssl
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from pytrat.client import (
    ExchangeRequest,
    MtlsCredential,
    PrivateKeyJwtCredential,
    SpiffeJwtSvidCredential,
    WorkloadCredential,
    build_issue_request,
)
from pytrat.core import ConfigurationError, DependencyError, ReasonCode, SecretToken
from pytrat.core.constants import CLIENT_ASSERTION_TYPE_JWT_BEARER, TOKEN_TYPE_ACCESS_TOKEN
from pytrat.core.crypto import private_key_to_pem, verify_signature
from pytrat.core.testing import FrozenClock, generate_test_key

ENDPOINT = "https://tts.internal/token"


def _request() -> ExchangeRequest:
    return build_issue_request(
        audience="payments.internal",
        scope="payments.transfer",
        subject_token=SecretToken("subject"),
        subject_token_type=TOKEN_TYPE_ACCESS_TOKEN,
    )


def _segment(raw: str, index: int) -> dict[str, object]:
    part = raw.split(".")[index]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))  # type: ignore[no-any-return]


@pytest.fixture
def key_file(tmp_path: Path):
    key = generate_test_key("ES256", kid="client-key-1")
    path = tmp_path / "client.pem"
    path.write_bytes(private_key_to_pem(key.private_key))
    return key, path


# ----------------------------------------------------------------------------- private_key_jwt


def test_private_key_jwt_adds_rfc7523_client_assertion(key_file) -> None:
    key, path = key_file
    clock = FrozenClock(1_800_000_000)
    credential = PrivateKeyJwtCredential(
        "gateway", path, alg="ES256", kid=key.kid, token_endpoint=ENDPOINT, clock=clock
    )
    assert isinstance(credential, WorkloadCredential)
    assert credential.client_id == "gateway"
    applied = credential.apply(_request())
    assert applied.form["client_id"] == "gateway"
    assert applied.form["client_assertion_type"] == CLIENT_ASSERTION_TYPE_JWT_BEARER
    assertion = applied.form["client_assertion"]
    header = _segment(assertion, 0)
    assert header == {"typ": "JWT", "alg": "ES256", "kid": key.kid}
    claims = verify_signature(assertion, key.public_key, "ES256")
    assert claims["iss"] == claims["sub"] == "gateway"
    assert claims["aud"] == ENDPOINT
    assert claims["iat"] == 1_800_000_000
    assert claims["exp"] - claims["iat"] <= 60  # type: ignore[operator]
    assert applied.form["subject_token"] == "subject"


def test_private_key_jwt_assertions_have_unique_jti(key_file) -> None:
    _, path = key_file
    credential = PrivateKeyJwtCredential(
        "gateway", path, alg="ES256", kid=None, token_endpoint=ENDPOINT
    )
    first = _segment(credential.assertion(), 1)
    second = _segment(credential.assertion(), 1)
    assert first["jti"] != second["jti"]
    assert "kid" not in _segment(credential.assertion(), 0)


def test_private_key_jwt_repr_never_shows_key_material(key_file) -> None:
    key, path = key_file
    credential = PrivateKeyJwtCredential(
        "gateway", path, alg="ES256", kid=key.kid, token_endpoint=ENDPOINT
    )
    text = repr(credential)
    assert "gateway" in text
    assert "PRIVATE" not in text
    assert path.read_text() not in text


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"lifetime": 0}, "lifetime"),
        ({"lifetime": 61}, "lifetime"),
        ({"alg": "HS256"}, "not permitted"),
        ({"alg": "RS256"}, "incompatible"),
        ({"client_id": ""}, "client_id"),
        ({"token_endpoint": ""}, "token_endpoint"),
    ],
)
def test_private_key_jwt_rejects_unsafe_configuration(key_file, overrides, message) -> None:
    _, path = key_file
    args: dict[str, object] = {
        "client_id": "gateway",
        "private_key_path": path,
        "alg": "ES256",
        "kid": "k",
        "token_endpoint": ENDPOINT,
        **overrides,
    }
    with pytest.raises(ConfigurationError, match=message):
        PrivateKeyJwtCredential(**args)  # type: ignore[arg-type]


def test_private_key_jwt_loads_only_from_a_readable_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="could not be read"):
        PrivateKeyJwtCredential(
            "gateway", tmp_path / "missing.pem", alg="ES256", kid="k", token_endpoint=ENDPOINT
        )
    bad = tmp_path / "bad.pem"
    bad.write_text("not a key")
    with pytest.raises(ConfigurationError):
        PrivateKeyJwtCredential("gateway", bad, alg="ES256", kid="k", token_endpoint=ENDPOINT)


def test_inline_pem_string_is_not_accepted_as_a_key(key_file) -> None:
    key, path = key_file
    pem = path.read_bytes()
    with pytest.raises(ConfigurationError):
        PrivateKeyJwtCredential(
            "gateway",
            pem,  # type: ignore[arg-type]
            alg="ES256",
            kid=key.kid,
            token_endpoint=ENDPOINT,
        )


# ----------------------------------------------------------------------------- mTLS


def _self_signed(tmp_path: Path) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "gateway")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


@pytest.fixture
def mtls(tmp_path: Path) -> MtlsCredential:
    cert_path, key_path = _self_signed(tmp_path)
    return MtlsCredential(cert_path, key_path, client_id="gateway", ca_path=cert_path)


def test_mtls_apply_adds_only_client_id(mtls: MtlsCredential) -> None:
    request = _request()
    applied = mtls.apply(request)
    assert set(applied.form) - set(request.form) == {"client_id"}
    assert applied.form["client_id"] == "gateway"


def test_mtls_exposes_a_verifying_ssl_context(mtls: MtlsCredential) -> None:
    context = mtls.ssl_context()
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname
    assert mtls.cert[0].endswith("cert.pem")
    assert "gateway" in repr(mtls)
    assert "key.pem" not in repr(mtls)


def test_mtls_unloadable_certificate_is_a_configuration_error(tmp_path: Path) -> None:
    credential = MtlsCredential(tmp_path / "nope.pem", tmp_path / "nope.key", client_id="gw")
    with pytest.raises(ConfigurationError):
        credential.ssl_context()
    with pytest.raises(ConfigurationError):
        MtlsCredential("c", "k", client_id="")


# ----------------------------------------------------------------------------- SPIFFE JWT-SVID


def test_spiffe_svid_is_reread_on_every_call(tmp_path: Path) -> None:
    svid = tmp_path / "svid.jwt"
    svid.write_text("aaa.bbb.ccc\n")
    credential = SpiffeJwtSvidCredential(svid, "spiffe://payments/gateway")
    first = credential.apply(_request())
    assert first.form["client_assertion"] == "aaa.bbb.ccc"
    assert first.form["client_assertion_type"] == CLIENT_ASSERTION_TYPE_JWT_BEARER
    assert first.form["client_id"] == "spiffe://payments/gateway"
    svid.write_text("ddd.eee.fff")  # rotated by the SPIFFE helper
    assert credential.apply(_request()).form["client_assertion"] == "ddd.eee.fff"
    assert "ddd" not in repr(credential)


@pytest.mark.parametrize(
    "content", [b"", b"not-a-jwt", b"a.b.c.d", b"a.b c.d", b"\xff\xfe.a.b", b"a" * 20000]
)
def test_spiffe_unusable_svid_fails_closed(tmp_path: Path, content: bytes) -> None:
    svid = tmp_path / "svid.jwt"
    svid.write_bytes(content)
    with pytest.raises(DependencyError) as excinfo:
        SpiffeJwtSvidCredential(svid, "gw").apply(_request())
    assert excinfo.value.reason is ReasonCode.DEPENDENCY_UNAVAILABLE


def test_spiffe_missing_svid_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(DependencyError):
        SpiffeJwtSvidCredential(tmp_path / "missing", "gw").apply(_request())
    with pytest.raises(ConfigurationError):
        SpiffeJwtSvidCredential(tmp_path / "missing", "")
