"""Shared test helpers and fixtures.

Provides a small builder to create self-signed X.509 certificates on the fly,
so the tests do not depend on any network access or stored fixture files.
"""

from datetime import datetime, timedelta, timezone
import ipaddress

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtendedKeyUsageOID,
    NameOID,
)


def build_certificate(
    *,
    common_name: str = "example.com",
    days_valid: int = 90,
    days_ago_start: int = 1,
    san: list[str] | None = ("example.com", "www.example.com"),
    san_ips: list[str] | None = None,
    key_size: int = 2048,
    ca: bool = False,
    issuer_name: str | None = None,
    sig_hash: hashes.HashAlgorithm | None = None,
    encoding: serialization.Encoding = serialization.Encoding.DER,
    ec_curve: ec.EllipticCurve | None = None,
    key_usage: x509.KeyUsage | None = None,
    extended_key_usage: list | None = None,
    must_staple: bool = False,
    aia_ca_issuers: str | None = None,
) -> bytes:
    """Build a self-signed certificate and return its serialized bytes.

    Args:
        common_name: CN used for the subject (and issuer unless overridden).
        days_valid: number of days from now until expiry (negative = expired).
        days_ago_start: how many days in the past the validity starts.
        san: list of DNS names for the SAN extension, or None to omit it.
        san_ips: list of IP-address strings to add to the SAN extension.
        key_size: RSA key size in bits.
        ca: whether to mark the certificate as a CA via BasicConstraints.
        issuer_name: CN to use for the issuer (defaults to common_name,
            which yields a self-signed certificate).
        sig_hash: hash algorithm used to sign (defaults to SHA-256).
        encoding: DER or PEM output encoding.
        ec_curve: if set, generate an EC key on this curve instead of RSA.
    """
    if ec_curve is not None:
        key = ec.generate_private_key(ec_curve)
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, issuer_name or common_name)]
    )
    now = datetime.now(timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=days_ago_start))
        .not_valid_after(now + timedelta(days=days_valid))
    )
    general_names = [x509.DNSName(n) for n in (san or [])]
    if san_ips:
        general_names += [x509.IPAddress(ipaddress.ip_address(ip)) for ip in san_ips]
    if general_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(general_names),
            critical=False,
        )
    if ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
    if key_usage is not None:
        builder = builder.add_extension(key_usage, critical=True)
    if extended_key_usage is not None:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(extended_key_usage), critical=False
        )
    if must_staple:
        builder = builder.add_extension(
            x509.TLSFeature([x509.TLSFeatureType.status_request]),
            critical=False,
        )

    if aia_ca_issuers is not None:
        builder = builder.add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.CA_ISSUERS,
                        x509.UniformResourceIdentifier(aia_ca_issuers),
                    )
                ]
            ),
            critical=False,
        )

    cert = builder.sign(key, sig_hash or hashes.SHA256())
    return cert.public_bytes(encoding)


@pytest.fixture
def make_cert():
    """Fixture returning the certificate builder helper."""
    return build_certificate


@pytest.fixture
def der_cert() -> bytes:
    """A valid DER-encoded certificate with a SAN extension."""
    return build_certificate()


@pytest.fixture
def pem_cert() -> bytes:
    """A valid PEM-encoded certificate with a SAN extension."""
    return build_certificate(encoding=serialization.Encoding.PEM)


def build_chain(
    *,
    leaf_cn: str = "leaf.example.com",
    leaf_san: list[str] | None = ("leaf.example.com",),
    leaf_days_valid: int = 90,
) -> tuple[x509.Certificate, x509.Certificate, x509.Certificate]:
    """Build a real (root, intermediate, leaf) chain and return them as objects.

    The root is self-signed, the intermediate is signed by the root, and the
    leaf is signed by the intermediate with a SAN and the serverAuth EKU, so the
    result passes the strict path validation used by offline verification.
    Returned leaf-first: ``(leaf, intermediate, root)``.
    """
    now = datetime.now(timezone.utc)

    def _key() -> rsa.RSAPrivateKey:
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def _name(cn: str) -> x509.Name:
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    ca_usage = x509.KeyUsage(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=True,
        crl_sign=True,
        encipher_only=False,
        decipher_only=False,
    )

    root_key = _key()
    root = (
        x509.CertificateBuilder()
        .subject_name(_name("Test Root CA"))
        .issuer_name(_name("Test Root CA"))
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(ca_usage, critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    inter_key = _key()
    intermediate = (
        x509.CertificateBuilder()
        .subject_name(_name("Test Intermediate CA"))
        .issuer_name(root.subject)
        .public_key(inter_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(ca_usage, critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(inter_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    leaf_key = _key()
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(leaf_cn))
        .issuer_name(intermediate.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=leaf_days_valid))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(inter_key.public_key()),
            critical=False,
        )
    )
    if leaf_san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in leaf_san]),
            critical=False,
        )
    leaf = builder.sign(inter_key, hashes.SHA256())
    return leaf, intermediate, root


@pytest.fixture
def make_chain():
    """Fixture returning the chain builder helper."""
    return build_chain
