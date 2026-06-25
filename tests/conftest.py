"""Shared test helpers and fixtures.

Provides a small builder to create self-signed X.509 certificates on the fly,
so the tests do not depend on any network access or stored fixture files.
"""

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID


def build_certificate(
    *,
    common_name: str = "example.com",
    days_valid: int = 90,
    days_ago_start: int = 1,
    san: list[str] | None = ("example.com", "www.example.com"),
    key_size: int = 2048,
    ca: bool = False,
    issuer_name: str | None = None,
    sig_hash: hashes.HashAlgorithm | None = None,
    encoding: serialization.Encoding = serialization.Encoding.DER,
    ec_curve: ec.EllipticCurve | None = None,
) -> bytes:
    """Build a self-signed certificate and return its serialized bytes.

    Args:
        common_name: CN used for the subject (and issuer unless overridden).
        days_valid: number of days from now until expiry (negative = expired).
        days_ago_start: how many days in the past the validity starts.
        san: list of DNS names for the SAN extension, or None to omit it.
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
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in san]),
            critical=False,
        )
    if ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
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
