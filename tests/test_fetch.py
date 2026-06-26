"""Tests for the network helpers that do not require a live server."""

import pytest

from certinspect.fetch import check_revocation
from certinspect.parser import load_certificate


def test_check_revocation_unavailable_without_aia(make_cert):
    cert = load_certificate(make_cert())
    status, detail = check_revocation(cert)
    assert status == "UNAVAILABLE"
    assert "AIA" in detail


def test_check_revocation_accepts_explicit_issuer(make_cert):
    cert = load_certificate(make_cert())
    # Passing an issuer must not require a network download; with no OCSP
    # responder in the certificate the result is still UNAVAILABLE.
    status, _ = check_revocation(cert, issuer=cert)
    assert status == "UNAVAILABLE"


def test_http_rejects_unsupported_scheme():
    from certinspect.fetch import _http

    with pytest.raises(ValueError, match="unsupported URL scheme"):
        _http("ftp://example.com/cert", timeout=1.0)


class _FakeSocket:
    """A minimal socket double scripted with the server's plaintext replies."""

    def __init__(self, script: bytes):
        self._inbox = bytearray(script)
        self.sent = bytearray()

    def recv(self, n: int) -> bytes:
        chunk = bytes(self._inbox[:n])
        del self._inbox[:n]
        return chunk

    def sendall(self, data: bytes) -> None:
        self.sent += data


@pytest.mark.parametrize(
    "protocol, script, command",
    [
        (
            "smtp",
            b"220 mail ready\r\n250-mail\r\n250 STARTTLS\r\n220 go ahead\r\n",
            b"STARTTLS\r\n",
        ),
        ("pop3", b"+OK ready\r\n+OK begin TLS\r\n", b"STLS\r\n"),
        ("imap", b"* OK ready\r\na001 OK begin TLS\r\n", b"a001 STARTTLS\r\n"),
        ("ftp", b"220 ready\r\n234 go ahead\r\n", b"AUTH TLS\r\n"),
    ],
)
def test_negotiate_starttls_success(protocol, script, command):
    from certinspect.fetch import _negotiate_starttls

    sock = _FakeSocket(script)
    _negotiate_starttls(sock, protocol)
    assert command in sock.sent


def test_negotiate_starttls_smtp_sends_ehlo():
    from certinspect.fetch import _negotiate_starttls

    sock = _FakeSocket(b"220 mail ready\r\n250 STARTTLS\r\n220 go ahead\r\n")
    _negotiate_starttls(sock, "smtp")
    assert b"EHLO" in sock.sent


def test_negotiate_starttls_server_refuses():
    from certinspect.fetch import _negotiate_starttls

    sock = _FakeSocket(b"220 mail ready\r\n250 ok\r\n454 TLS not available\r\n")
    with pytest.raises(ValueError, match="unexpected STARTTLS reply"):
        _negotiate_starttls(sock, "smtp")


def test_negotiate_starttls_unsupported_protocol():
    from certinspect.fetch import _negotiate_starttls

    with pytest.raises(ValueError, match="unsupported STARTTLS protocol"):
        _negotiate_starttls(_FakeSocket(b""), "xmpp")


def test_verify_chain_uses_custom_ca(monkeypatch):
    """--cafile/--capath must build the SSL context from the given bundle."""
    import ssl

    from certinspect import fetch

    recorded = {}

    class _Conn:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    class _Context:
        def wrap_socket(self, sock, server_hostname=None):
            err = ssl.SSLCertVerificationError("self signed certificate")
            err.verify_message = "self signed certificate"
            raise err

    def _fake_create(*args, **kwargs):
        recorded["kwargs"] = kwargs
        return _Context()

    monkeypatch.setattr(fetch.ssl, "create_default_context", _fake_create)
    monkeypatch.setattr(fetch.socket, "create_connection", lambda *a, **k: _Conn())

    trusted, reason, chain = fetch.verify_chain(
        "example.com", cafile="/tmp/ca.pem", capath="/tmp/certs"
    )

    assert recorded["kwargs"] == {"cafile": "/tmp/ca.pem", "capath": "/tmp/certs"}
    assert trusted is False
    assert reason == "self signed certificate"
    assert chain == []


def test_verify_chain_default_uses_system_store(monkeypatch):
    """Without --cafile/--capath the system trust store is used (no kwargs)."""
    import ssl

    from certinspect import fetch

    recorded = {}

    class _Conn:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    class _Context:
        def wrap_socket(self, sock, server_hostname=None):
            err = ssl.SSLCertVerificationError("unable to get local issuer")
            err.verify_message = "unable to get local issuer"
            raise err

    def _fake_create(*args, **kwargs):
        recorded["kwargs"] = kwargs
        return _Context()

    monkeypatch.setattr(fetch.ssl, "create_default_context", _fake_create)
    monkeypatch.setattr(fetch.socket, "create_connection", lambda *a, **k: _Conn())

    fetch.verify_chain("example.com")

    assert recorded["kwargs"] == {}


# --- CRL fallback -----------------------------------------------------------

CRL_URL = "http://crl.example.com/ca.crl"


def _build_crl_pki(revoked_serials=()):
    """Build a (issuer_cert, leaf_cert, crl) triple for CRL tests.

    The issuer is a self-signed CA; the leaf carries a CRLDistributionPoints
    extension pointing at ``CRL_URL`` and is signed by the issuer. The CRL is
    signed by the issuer and revokes every serial in ``revoked_serials``.
    """
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    now = datetime.now(timezone.utc)
    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
    issuer_cert = (
        x509.CertificateBuilder()
        .subject_name(issuer_name)
        .issuer_name(issuer_name)
        .public_key(issuer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(issuer_key, hashes.SHA256())
    )

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")]))
        .issuer_name(issuer_name)
        .public_key(leaf_key.public_key())
        .serial_number(4242)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(CRL_URL)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )
        .sign(issuer_key, hashes.SHA256())
    )

    crl_builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_name)
        .last_update(now - timedelta(hours=1))
        .next_update(now + timedelta(days=1))
    )
    for serial in revoked_serials:
        crl_builder = crl_builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(now - timedelta(hours=2))
            .build()
        )
    crl = crl_builder.sign(issuer_key, hashes.SHA256())
    return issuer_cert, leaf_cert, crl


def test_crl_urls_extracts_http_distribution_points():
    from cryptography.hazmat.primitives import serialization

    from certinspect.fetch import _crl_urls

    _, leaf_cert, _ = _build_crl_pki()
    leaf = load_certificate(leaf_cert.public_bytes(serialization.Encoding.DER))
    assert _crl_urls(leaf) == [CRL_URL]


def test_check_crl_reports_good_when_serial_absent(monkeypatch):
    from cryptography.hazmat.primitives import serialization

    from certinspect import fetch

    issuer_cert, leaf_cert, crl = _build_crl_pki(revoked_serials=())
    der_crl = crl.public_bytes(serialization.Encoding.DER)
    monkeypatch.setattr(fetch, "_http", lambda url, timeout: der_crl)

    status, detail = fetch._check_crl(leaf_cert, issuer_cert, timeout=1.0)
    assert status == "GOOD"
    assert detail == "via CRL"


def test_check_crl_reports_revoked_when_serial_listed(monkeypatch):
    from cryptography.hazmat.primitives import serialization

    from certinspect import fetch

    issuer_cert, leaf_cert, crl = _build_crl_pki(revoked_serials=(4242,))
    der_crl = crl.public_bytes(serialization.Encoding.DER)
    monkeypatch.setattr(fetch, "_http", lambda url, timeout: der_crl)

    status, detail = fetch._check_crl(leaf_cert, issuer_cert, timeout=1.0)
    assert status == "REVOKED"
    assert "via CRL" in detail


def test_check_crl_skips_crl_with_bad_signature(monkeypatch):
    """A CRL not signed by the issuer is ignored (soft-fail)."""
    from cryptography.hazmat.primitives import serialization

    from certinspect import fetch

    _, leaf_cert, _ = _build_crl_pki(revoked_serials=(4242,))
    # CRL signed by an unrelated CA must not be trusted against this issuer.
    other_issuer, _, other_crl = _build_crl_pki(revoked_serials=(4242,))
    der_crl = other_crl.public_bytes(serialization.Encoding.DER)
    monkeypatch.setattr(fetch, "_http", lambda url, timeout: der_crl)

    # Use the first PKI's issuer, whose key did not sign ``other_crl``.
    wrong_issuer, _, _ = _build_crl_pki()
    status, _ = fetch._check_crl(leaf_cert, wrong_issuer, timeout=1.0)
    assert status == "UNAVAILABLE"


def test_check_revocation_falls_back_to_crl(monkeypatch):
    """With no OCSP responder, check_revocation consults the CRL."""
    from cryptography.hazmat.primitives import serialization

    from certinspect import fetch

    issuer_cert, leaf_cert, crl = _build_crl_pki(revoked_serials=(4242,))
    der_crl = crl.public_bytes(serialization.Encoding.DER)
    monkeypatch.setattr(fetch, "_http", lambda url, timeout: der_crl)

    status, detail = fetch.check_revocation(leaf_cert, issuer=issuer_cert)
    assert status == "REVOKED"
    assert "via CRL" in detail
