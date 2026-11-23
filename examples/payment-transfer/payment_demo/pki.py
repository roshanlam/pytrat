"""Fresh key material for the Docker Compose deployment: a demo CA, TLS certificates, JWT keys.

Run once per deployment by the ``init`` container. Nothing here is ever committed or baked into an
image; it lives only in Docker volumes and disappears with ``docker compose down -v``.

Layout written by :func:`provision`::

    <public>/ca.crt                      demo CA certificate (every container trusts only this)
    <public>/<name>.jwks.json            public JWKS of each JWT key in KEY_NAMES
    <private>/<service>/tls.{crt,key}    the service's TLS certificate and key (0600)
    <private>/<service>/<name>.pem       JWT signing keys owned by that service (0600)

The CA private key is generated in memory, used to sign the leaf certificates and then discarded:
it is never written anywhere, so nothing can mint further certificates for this deployment.
"""

from __future__ import annotations

import datetime
import ipaddress
import json
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from pytrat.cli._demo.lab import ALG, KEY_NAMES, verification_key, write_private
from pytrat.core import StaticKeySet
from pytrat.core.crypto import generate_private_key, private_key_to_pem

CERT_LIFETIME = datetime.timedelta(days=7)
COMPLETE_MARKER = ".complete"

# Which service's private volume holds each JWT signing key. The ledger signs nothing; the
# "client" volume holds the identity-provider key the demo user's client uses to mint a login.
KEY_OWNERS: Mapping[str, str] = {
    "tts": "tts",
    "api-gateway": "gateway",
    "payment-service": "payment",
    "idp": "client",
}


@dataclass(frozen=True, slots=True)
class TlsService:
    """A service that terminates TLS, and the names its certificate is valid for."""

    name: str
    dns_names: Sequence[str]
    ip_addresses: Sequence[str] = ()


def _name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PyTraT demo"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _san(service: TlsService) -> x509.SubjectAlternativeName:
    names: list[x509.GeneralName] = [x509.DNSName(name) for name in service.dns_names]
    names += [x509.IPAddress(ipaddress.ip_address(ip)) for ip in service.ip_addresses]
    return x509.SubjectAlternativeName(names)


def _issue_ca(
    services: Sequence[TlsService], now: datetime.datetime
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    # Name constraints: even a leaked copy of this CA certificate can only ever vouch for the
    # demo's own service names, never for a real host.
    permitted: list[x509.GeneralName] = []
    for service in services:
        permitted += [x509.DNSName(name) for name in service.dns_names]
        permitted += [
            x509.IPAddress(ipaddress.ip_network(f"{ip}/32")) for ip in service.ip_addresses
        ]
    certificate = (
        x509.CertificateBuilder()
        .subject_name(_name("PyTraT demo CA (ephemeral)"))
        .issuer_name(_name("PyTraT demo CA (ephemeral)"))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + CERT_LIFETIME)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.NameConstraints(permitted_subtrees=permitted, excluded_subtrees=None),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def _issue_leaf(
    service: TlsService,
    ca_key: ec.EllipticCurvePrivateKey,
    ca_certificate: x509.Certificate,
    now: datetime.datetime,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    certificate = (
        x509.CertificateBuilder()
        .subject_name(_name(service.dns_names[0]))
        .issuer_name(ca_certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + CERT_LIFETIME)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(_san(service), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return key, certificate


def _pem_certificate(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.PEM)


def _pem_key(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def provision(
    public_dir: Path,
    private_root: Path,
    services: Sequence[TlsService],
    *,
    now: datetime.datetime | None = None,
) -> bool:
    """Generate all key material, unless a previous run already completed.

    Material is generated once per volume lifetime, so restarting ``init`` (for example on a
    second ``docker compose up``) never swaps keys under running services.

    Args:
        public_dir: Shared, world-readable directory for the CA certificate and JWKS files.
        private_root: Directory holding one private subdirectory per service.
        services: The services that need TLS certificates.
        now: Certificate validity start (defaults to the current time).

    Returns:
        True if fresh material was generated, False if existing material was kept.
    """
    if (public_dir / COMPLETE_MARKER).exists():
        return False
    issued_at = now or datetime.datetime.now(datetime.UTC)
    ca_key, ca_certificate = _issue_ca(services, issued_at)
    for owner in {service.name for service in services} | set(KEY_OWNERS.values()):
        (private_root / owner).mkdir(mode=0o700, parents=True, exist_ok=True)
    for service in services:
        key, certificate = _issue_leaf(service, ca_key, ca_certificate, issued_at)
        directory = private_root / service.name
        write_private(directory / "tls.key", _pem_key(key))
        write_private(directory / "tls.crt", _pem_certificate(certificate))
    del ca_key  # never persisted: no further certificates can be issued for this deployment

    for name in KEY_NAMES:
        private_key = generate_private_key(ALG)
        write_private(
            private_root / KEY_OWNERS[name] / f"{name}.pem", private_key_to_pem(private_key)
        )
        jwks = StaticKeySet([verification_key(name, private_key)]).to_jwks()
        _write_public(public_dir / f"{name}.jwks.json", json.dumps(jwks, indent=2).encode())
    _write_public(public_dir / "ca.crt", _pem_certificate(ca_certificate))
    _write_public(public_dir / COMPLETE_MARKER, b"")
    return True


def _write_public(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)
