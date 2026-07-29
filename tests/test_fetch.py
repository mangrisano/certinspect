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
        self.closed = False

    def recv(self, n: int) -> bytes:
        chunk = bytes(self._inbox[:n])
        del self._inbox[:n]
        return chunk

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def close(self) -> None:
        self.closed = True


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


def test_open_socket_direct_when_no_proxy(monkeypatch):
    from certinspect import fetch

    sentinel = object()
    monkeypatch.setattr(
        fetch.socket, "create_connection", lambda addr, timeout=None: sentinel
    )
    assert fetch._open_socket("example.com", 443, 5.0) is sentinel


def test_open_socket_proxy_sends_connect(monkeypatch):
    from certinspect import fetch

    fake = _FakeSocket(b"HTTP/1.1 200 Connection established\r\n\r\n")
    monkeypatch.setattr(
        fetch.socket, "create_connection", lambda addr, timeout=None: fake
    )
    sock = fetch._open_socket("example.com", 443, 5.0, "http://proxy:8080")
    assert sock is fake
    assert b"CONNECT example.com:443 HTTP/1.1" in bytes(fake.sent)


def test_open_socket_proxy_sends_auth(monkeypatch):
    from certinspect import fetch

    fake = _FakeSocket(b"HTTP/1.1 200 OK\r\n\r\n")
    monkeypatch.setattr(
        fetch.socket, "create_connection", lambda addr, timeout=None: fake
    )
    fetch._open_socket("example.com", 443, 5.0, "http://user:pass@proxy:8080")
    assert b"Proxy-Authorization: Basic " in bytes(fake.sent)


def test_open_socket_proxy_refused_raises_and_closes(monkeypatch):
    from certinspect import fetch

    fake = _FakeSocket(b"HTTP/1.1 403 Forbidden\r\n\r\n")
    monkeypatch.setattr(
        fetch.socket, "create_connection", lambda addr, timeout=None: fake
    )
    with pytest.raises(ValueError, match="proxy CONNECT"):
        fetch._open_socket("example.com", 443, 5.0, "http://proxy:8080")
    assert fake.closed is True


def test_resolve_proxy_explicit_wins(monkeypatch):
    from certinspect import fetch

    monkeypatch.setattr(fetch.urllib.request, "getproxies", lambda: {})
    assert (
        fetch._resolve_proxy("example.com", "http://p:8080", False) == "http://p:8080"
    )


def test_resolve_proxy_no_proxy_forces_direct(monkeypatch):
    from certinspect import fetch

    monkeypatch.setattr(
        fetch.urllib.request, "getproxies", lambda: {"https": "http://p:8080"}
    )
    assert fetch._resolve_proxy("example.com", None, True) is None


def test_resolve_proxy_falls_back_to_environment(monkeypatch):
    from certinspect import fetch

    monkeypatch.setattr(
        fetch.urllib.request, "getproxies", lambda: {"https": "http://env:3128"}
    )
    monkeypatch.setattr(fetch.urllib.request, "proxy_bypass", lambda host: False)
    assert fetch._resolve_proxy("example.com", None, False) == "http://env:3128"


def test_resolve_proxy_honours_no_proxy_bypass(monkeypatch):
    from certinspect import fetch

    monkeypatch.setattr(
        fetch.urllib.request, "getproxies", lambda: {"https": "http://env:3128"}
    )
    monkeypatch.setattr(fetch.urllib.request, "proxy_bypass", lambda host: True)
    assert fetch._resolve_proxy("internal.local", None, False) is None


def test_resolve_proxy_direct_without_environment(monkeypatch):
    from certinspect import fetch

    monkeypatch.setattr(fetch.urllib.request, "getproxies", lambda: {})
    assert fetch._resolve_proxy("example.com", None, False) is None


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


def test_verify_chain_ignores_hostname(monkeypatch):
    """Chain trust is validated independently of the hostname (reported apart as
    hostname_match), so verify_chain must disable check_hostname."""
    import ssl

    from certinspect import fetch

    recorded = {}

    class _Conn:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    class _Context:
        check_hostname = True

        def wrap_socket(self, sock, server_hostname=None):
            recorded["check_hostname"] = self.check_hostname
            err = ssl.SSLCertVerificationError("boom")
            err.verify_message = "boom"
            raise err

    monkeypatch.setattr(fetch.ssl, "create_default_context", lambda *a, **k: _Context())
    monkeypatch.setattr(fetch.socket, "create_connection", lambda *a, **k: _Conn())

    fetch.verify_chain("example.com")

    assert recorded["check_hostname"] is False


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


OCSP_URL = "http://ocsp.example.com"


def _build_ocsp_pki():
    """Build a (issuer_cert, leaf_cert) pair whose leaf advertises an OCSP
    responder in its AIA extension, for OCSP soft-fail tests."""
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

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
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier(OCSP_URL),
                    )
                ]
            ),
            critical=False,
        )
        .sign(issuer_key, hashes.SHA256())
    )
    return issuer_cert, leaf_cert


def test_check_ocsp_soft_fails_on_unparseable_response(monkeypatch):
    """A malformed OCSP response must degrade to UNAVAILABLE, not raise.

    Some responders (e.g. DigiCert/GitHub) return a BasicOCSPResponse whose
    signatureAlgorithm the strict ASN.1 parser rejects with a ValueError. That
    must not abort the inspection — the revocation check soft-fails instead.
    """
    from certinspect import fetch

    issuer_cert, leaf_cert = _build_ocsp_pki()
    # Garbage bytes that load_der_ocsp_response cannot parse.
    monkeypatch.setattr(
        fetch, "_http", lambda url, data=None, timeout=None: b"\x30\x03not-asn1"
    )

    status, detail = fetch._check_ocsp(leaf_cert, issuer_cert, timeout=1.0)
    assert status == "UNAVAILABLE"
    assert "could not be parsed" in detail


# --- SSRF guard and response-size cap ---------------------------------------


def _addrinfo(ip: str):
    """Return a getaddrinfo-shaped result resolving a host to ``ip``."""
    import socket as _socket

    family = _socket.AF_INET6 if ":" in ip else _socket.AF_INET
    return [(family, _socket.SOCK_STREAM, 6, "", (ip, 0))]


@pytest.mark.parametrize(
    "ip",
    ["127.0.0.1", "169.254.169.254", "0.0.0.0", "::1", "224.0.0.1"],
)
def test_guard_fetch_host_blocks_internal_addresses(monkeypatch, ip):
    """Loopback, link-local (cloud metadata), unspecified and multicast
    targets from a certificate URL must be refused."""
    from certinspect import fetch

    monkeypatch.setattr(fetch.socket, "getaddrinfo", lambda *a, **k: _addrinfo(ip))
    with pytest.raises(ValueError, match="non-routable or internal"):
        fetch._guard_fetch_host("http://danger.example/x")


def test_guard_fetch_host_allows_private_pki(monkeypatch):
    """An internal PKI on an RFC1918 address must stay reachable."""
    from certinspect import fetch

    monkeypatch.setattr(
        fetch.socket, "getaddrinfo", lambda *a, **k: _addrinfo("10.10.0.5")
    )
    assert fetch._guard_fetch_host("http://ocsp.internal.lan/") is None


def test_http_refuses_link_local_metadata_address(monkeypatch):
    """The guard is wired into _http, so a metadata URL raises before urlopen."""
    from certinspect import fetch

    monkeypatch.setattr(
        fetch.socket, "getaddrinfo", lambda *a, **k: _addrinfo("169.254.169.254")
    )
    with pytest.raises(ValueError, match="non-routable or internal"):
        fetch._http("http://metadata.example/ocsp", timeout=1.0)


def test_http_caps_oversized_response(monkeypatch):
    """A response larger than the cap is rejected instead of read in full."""
    from certinspect import fetch

    monkeypatch.setattr(fetch, "_guard_fetch_host", lambda url: None)
    monkeypatch.setattr(fetch, "_MAX_HTTP_RESPONSE_BYTES", 10)

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self, amt=-1):
            return b"x" * amt

    monkeypatch.setattr(fetch.urllib.request, "urlopen", lambda *a, **k: _Resp())
    with pytest.raises(ValueError, match="exceeds the"):
        fetch._http("http://big.example/crl", timeout=1.0)


# --- OCSP response freshness ------------------------------------------------


def _signed_ocsp(cert_status, this_update, next_update):
    """Build a signed OCSP response for a fresh single-CA OCSP PKI.

    Returns ``(issuer_cert, leaf_cert, der_response)``; the responder is the
    issuer itself, matching the common single-CA deployment.
    """
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509 import ocsp
    from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

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
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier(OCSP_URL),
                    )
                ]
            ),
            critical=False,
        )
        .sign(issuer_key, hashes.SHA256())
    )
    response = (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=leaf_cert,
            issuer=issuer_cert,
            algorithm=hashes.SHA1(),
            cert_status=cert_status,
            this_update=this_update,
            next_update=next_update,
            revocation_time=None,
            revocation_reason=None,
        )
        .responder_id(ocsp.OCSPResponderEncoding.NAME, issuer_cert)
        .sign(issuer_key, hashes.SHA256())
    )
    return issuer_cert, leaf_cert, response.public_bytes(serialization.Encoding.DER)


def test_check_ocsp_good_when_response_is_fresh(monkeypatch):
    from datetime import datetime, timedelta, timezone

    from cryptography.x509 import ocsp

    from certinspect import fetch

    now = datetime.now(timezone.utc)
    issuer_cert, leaf_cert, der = _signed_ocsp(
        ocsp.OCSPCertStatus.GOOD, now - timedelta(hours=1), now + timedelta(days=1)
    )
    monkeypatch.setattr(fetch, "_http", lambda url, data=None, timeout=None: der)

    status, _ = fetch._check_ocsp(leaf_cert, issuer_cert, timeout=1.0)
    assert status == "GOOD"


def test_check_ocsp_soft_fails_on_stale_response(monkeypatch):
    """A GOOD response whose nextUpdate has passed must degrade to UNAVAILABLE,
    so a replayed stale answer cannot mask a later revocation."""
    from datetime import datetime, timedelta, timezone

    from cryptography.x509 import ocsp

    from certinspect import fetch

    now = datetime.now(timezone.utc)
    issuer_cert, leaf_cert, der = _signed_ocsp(
        ocsp.OCSPCertStatus.GOOD, now - timedelta(days=2), now - timedelta(days=1)
    )
    monkeypatch.setattr(fetch, "_http", lambda url, data=None, timeout=None: der)

    status, detail = fetch._check_ocsp(leaf_cert, issuer_cert, timeout=1.0)
    assert status == "UNAVAILABLE"
    assert "stale" in detail
