"""Tests for the network helpers that do not require a live server."""

import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from certinspect.revocation import check_revocation
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
    from certinspect.httpfetch import fetch

    with pytest.raises(ValueError, match="unsupported URL scheme"):
        fetch("ftp://example.com/cert", timeout=1.0)


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

    def settimeout(self, timeout) -> None:
        pass


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

    recorded = {}

    class _Sock:
        def settimeout(self, timeout):
            recorded["read_timeout"] = timeout

    sock = _Sock()

    def _create(addr, timeout=None):
        recorded["connect_timeout"] = timeout
        return sock

    monkeypatch.setattr(fetch.socket, "create_connection", _create)
    assert fetch._open_socket("example.com", 443, 3.0, 5.0) is sock
    assert recorded == {"connect_timeout": 3.0, "read_timeout": 5.0}


def test_open_socket_proxy_sends_connect(monkeypatch):
    from certinspect import fetch

    fake = _FakeSocket(b"HTTP/1.1 200 Connection established\r\n\r\n")
    monkeypatch.setattr(
        fetch.socket, "create_connection", lambda addr, timeout=None: fake
    )
    sock = fetch._open_socket("example.com", 443, 5.0, 5.0, "http://proxy:8080")
    assert sock is fake
    assert b"CONNECT example.com:443 HTTP/1.1" in bytes(fake.sent)


def test_open_socket_proxy_sends_auth(monkeypatch):
    from certinspect import fetch

    fake = _FakeSocket(b"HTTP/1.1 200 OK\r\n\r\n")
    monkeypatch.setattr(
        fetch.socket, "create_connection", lambda addr, timeout=None: fake
    )
    fetch._open_socket("example.com", 443, 5.0, 5.0, "http://user:pass@proxy:8080")
    assert b"Proxy-Authorization: Basic " in bytes(fake.sent)


def test_open_socket_proxy_refused_raises_and_closes(monkeypatch):
    from certinspect import fetch

    fake = _FakeSocket(b"HTTP/1.1 403 Forbidden\r\n\r\n")
    monkeypatch.setattr(
        fetch.socket, "create_connection", lambda addr, timeout=None: fake
    )
    with pytest.raises(ValueError, match="proxy CONNECT"):
        fetch._open_socket("example.com", 443, 5.0, 5.0, "http://proxy:8080")
    assert fake.closed is True


def test_split_timeout_from_float():
    from certinspect import fetch

    assert fetch._split_timeout(5.0) == (5.0, 5.0)


def test_split_timeout_from_tuple():
    from certinspect import fetch

    assert fetch._split_timeout((2.0, 8.0)) == (2.0, 8.0)


def test_retry_network_retries_then_succeeds(monkeypatch):
    from certinspect import fetch

    monkeypatch.setattr(fetch.time, "sleep", lambda s: None)
    calls = {"n": 0}

    def _call():
        calls["n"] += 1
        if calls["n"] < 3:
            raise ConnectionError("transient")
        return "ok"

    assert fetch.retry_network(_call, retries=3) == "ok"
    assert calls["n"] == 3


def test_retry_network_gives_up_and_raises(monkeypatch):
    from certinspect import fetch

    monkeypatch.setattr(fetch.time, "sleep", lambda s: None)
    calls = {"n": 0}

    def _call():
        calls["n"] += 1
        raise TimeoutError("nope")

    with pytest.raises(TimeoutError):
        fetch.retry_network(_call, retries=2)
    assert calls["n"] == 3  # the initial attempt plus two retries


def test_retry_network_does_not_retry_non_transient(monkeypatch):
    from certinspect import fetch

    monkeypatch.setattr(fetch.time, "sleep", lambda s: None)
    calls = {"n": 0}

    def _call():
        calls["n"] += 1
        raise ValueError("not a network error")

    with pytest.raises(ValueError):
        fetch.retry_network(_call, retries=3)
    assert calls["n"] == 1


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


class _EndlessSocket(_FakeSocket):
    """A hostile server that repeats ``pattern`` forever after an optional prefix."""

    _SAFETY_CAP = 1_000_000

    def __init__(self, pattern: bytes, prefix: bytes = b""):
        super().__init__(b"")
        self._stream = prefix
        self._pattern = pattern
        self.read = 0

    def recv(self, n: int) -> bytes:
        if self.read >= self._SAFETY_CAP:
            raise AssertionError("client kept reading an endless STARTTLS stream")
        if self.read < len(self._stream):
            byte = self._stream[self.read]
        else:
            byte = self._pattern[(self.read - len(self._stream)) % len(self._pattern)]
        self.read += 1
        return bytes([byte])


def test_negotiate_starttls_rejects_an_endless_line():
    from certinspect.fetch import _negotiate_starttls

    with pytest.raises(ValueError, match="line too long"):
        _negotiate_starttls(_EndlessSocket(b"A", prefix=b"220 "), "smtp")


@pytest.mark.parametrize(
    "protocol, prefix, pattern",
    [
        ("smtp", b"", b"220-greeting\r\n"),
        ("smtp", b"220 ready\r\n", b"250-EXTENSION\r\n"),
        ("ftp", b"", b"220-banner\r\n"),
        ("imap", b"* OK ready\r\n", b"* CAPABILITY IMAP4rev1\r\n"),
    ],
)
def test_negotiate_starttls_rejects_endless_replies(protocol, prefix, pattern):
    from certinspect.fetch import _negotiate_starttls

    with pytest.raises(ValueError, match="too many lines"):
        _negotiate_starttls(_EndlessSocket(pattern, prefix=prefix), protocol)


class _DrippingSocket(_EndlessSocket):
    """A hostile server sending one byte per ``delay``, below any read timeout."""

    def __init__(self, pattern: bytes, prefix: bytes = b"", delay: float = 0.02):
        super().__init__(pattern, prefix=prefix)
        self._delay = delay
        self._give_up = time.monotonic() + 5.0

    def recv(self, n: int) -> bytes:
        if time.monotonic() > self._give_up:
            raise AssertionError("client kept reading a dripping stream")
        time.sleep(self._delay)
        return super().recv(n)


def test_negotiate_starttls_bounds_a_dripped_reply():
    from certinspect.fetch import _negotiate_starttls

    start = time.monotonic()
    with pytest.raises(TimeoutError, match="took longer than 0.2s"):
        _negotiate_starttls(_DrippingSocket(b"x", prefix=b"220 "), "smtp", 0.2)
    assert time.monotonic() - start < 1.0


def test_open_socket_bounds_a_dripped_proxy_reply(monkeypatch):
    from certinspect import fetch

    dripping = _DrippingSocket(b"X-Padding: x\r\n", prefix=b"HTTP/1.1 200 OK\r\n")
    monkeypatch.setattr(
        fetch.socket, "create_connection", lambda addr, timeout=None: dripping
    )
    with pytest.raises(TimeoutError):
        fetch._open_socket("example.com", 443, 0.2, 5.0, "http://proxy:8080")
    assert dripping.closed is True


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

        def settimeout(self, timeout):
            pass

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

        def settimeout(self, timeout):
            pass

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

        def settimeout(self, timeout):
            pass

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


def _build_crl_pki(
    revoked_serials=(),
    *,
    crl_last_update_delta=None,
    crl_next_update_delta=None,
):
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
    if crl_last_update_delta is None:
        crl_last_update_delta = -timedelta(hours=1)
    if crl_next_update_delta is None:
        crl_next_update_delta = timedelta(days=1)
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
        .last_update(now + crl_last_update_delta)
        .next_update(now + crl_next_update_delta)
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

    from certinspect.revocation import _crl_urls

    _, leaf_cert, _ = _build_crl_pki()
    leaf = load_certificate(leaf_cert.public_bytes(serialization.Encoding.DER))
    assert _crl_urls(leaf) == [CRL_URL]


def test_check_crl_reports_good_when_serial_absent(monkeypatch):
    from cryptography.hazmat.primitives import serialization

    from certinspect import revocation

    issuer_cert, leaf_cert, crl = _build_crl_pki(revoked_serials=())
    der_crl = crl.public_bytes(serialization.Encoding.DER)
    monkeypatch.setattr(revocation, "fetch", lambda url, timeout: der_crl)

    status, detail = revocation._check_crl(leaf_cert, issuer_cert, timeout=1.0)
    assert status == "GOOD"
    assert detail == "via CRL"


def test_check_crl_reports_revoked_when_serial_listed(monkeypatch):
    from cryptography.hazmat.primitives import serialization

    from certinspect import revocation

    issuer_cert, leaf_cert, crl = _build_crl_pki(revoked_serials=(4242,))
    der_crl = crl.public_bytes(serialization.Encoding.DER)
    monkeypatch.setattr(revocation, "fetch", lambda url, timeout: der_crl)

    status, detail = revocation._check_crl(leaf_cert, issuer_cert, timeout=1.0)
    assert status == "REVOKED"
    assert "via CRL" in detail


def test_check_crl_soft_fails_stale_crl_when_serial_absent(monkeypatch):
    from datetime import timedelta

    from cryptography.hazmat.primitives import serialization

    from certinspect import revocation

    issuer_cert, leaf_cert, crl = _build_crl_pki(
        revoked_serials=(),
        crl_last_update_delta=-timedelta(days=2),
        crl_next_update_delta=-timedelta(days=1),
    )
    der_crl = crl.public_bytes(serialization.Encoding.DER)
    monkeypatch.setattr(revocation, "fetch", lambda url, timeout: der_crl)

    status, detail = revocation._check_crl(leaf_cert, issuer_cert, timeout=1.0)
    assert status == "UNAVAILABLE"
    assert "stale" in detail


def test_check_crl_reports_revoked_even_when_crl_is_stale(monkeypatch):
    from datetime import timedelta

    from cryptography.hazmat.primitives import serialization

    from certinspect import revocation

    issuer_cert, leaf_cert, crl = _build_crl_pki(
        revoked_serials=(4242,),
        crl_last_update_delta=-timedelta(days=2),
        crl_next_update_delta=-timedelta(days=1),
    )
    der_crl = crl.public_bytes(serialization.Encoding.DER)
    monkeypatch.setattr(revocation, "fetch", lambda url, timeout: der_crl)

    status, detail = revocation._check_crl(leaf_cert, issuer_cert, timeout=1.0)
    assert status == "REVOKED"
    assert "via CRL" in detail


def test_check_crl_soft_fails_not_yet_valid_crl_when_serial_absent(monkeypatch):
    from datetime import timedelta

    from cryptography.hazmat.primitives import serialization

    from certinspect import revocation

    issuer_cert, leaf_cert, crl = _build_crl_pki(
        revoked_serials=(),
        crl_last_update_delta=timedelta(days=1),
        crl_next_update_delta=timedelta(days=2),
    )
    der_crl = crl.public_bytes(serialization.Encoding.DER)
    monkeypatch.setattr(revocation, "fetch", lambda url, timeout: der_crl)

    status, detail = revocation._check_crl(leaf_cert, issuer_cert, timeout=1.0)
    assert status == "UNAVAILABLE"
    assert "not yet valid" in detail


def test_check_crl_skips_crl_with_bad_signature(monkeypatch):
    """A CRL not signed by the issuer is ignored (soft-fail)."""
    from cryptography.hazmat.primitives import serialization

    from certinspect import revocation

    _, leaf_cert, _ = _build_crl_pki(revoked_serials=(4242,))
    # CRL signed by an unrelated CA must not be trusted against this issuer.
    other_issuer, _, other_crl = _build_crl_pki(revoked_serials=(4242,))
    der_crl = other_crl.public_bytes(serialization.Encoding.DER)
    monkeypatch.setattr(revocation, "fetch", lambda url, timeout: der_crl)

    # Use the first PKI's issuer, whose key did not sign ``other_crl``.
    wrong_issuer, _, _ = _build_crl_pki()
    status, _ = revocation._check_crl(leaf_cert, wrong_issuer, timeout=1.0)
    assert status == "UNAVAILABLE"


def test_check_revocation_falls_back_to_crl(monkeypatch):
    """With no OCSP responder, check_revocation consults the CRL."""
    from cryptography.hazmat.primitives import serialization

    from certinspect import revocation

    issuer_cert, leaf_cert, crl = _build_crl_pki(revoked_serials=(4242,))
    der_crl = crl.public_bytes(serialization.Encoding.DER)
    monkeypatch.setattr(revocation, "fetch", lambda url, timeout: der_crl)

    status, detail = revocation.check_revocation(leaf_cert, issuer=issuer_cert)
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
    from certinspect import revocation

    issuer_cert, leaf_cert = _build_ocsp_pki()
    # Garbage bytes that load_der_ocsp_response cannot parse.
    monkeypatch.setattr(
        revocation, "fetch", lambda url, data=None, timeout=None: b"\x30\x03not-asn1"
    )

    status, detail = revocation._check_ocsp(leaf_cert, issuer_cert, timeout=1.0)
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
    from certinspect import httpfetch

    monkeypatch.setattr(httpfetch.socket, "getaddrinfo", lambda *a, **k: _addrinfo(ip))
    with pytest.raises(ValueError, match="non-routable or internal"):
        httpfetch._guard_fetch_host("http://danger.example/x")


def test_guard_fetch_host_allows_private_pki(monkeypatch):
    """An internal PKI on an RFC1918 address must stay reachable."""
    from certinspect import httpfetch

    monkeypatch.setattr(
        httpfetch.socket, "getaddrinfo", lambda *a, **k: _addrinfo("10.10.0.5")
    )
    assert httpfetch._guard_fetch_host("http://ocsp.internal.lan/") is None


def test_http_refuses_link_local_metadata_address(monkeypatch):
    """The guard is wired into fetch, so a metadata URL raises before urlopen."""
    from certinspect import httpfetch

    monkeypatch.setattr(
        httpfetch.socket, "getaddrinfo", lambda *a, **k: _addrinfo("169.254.169.254")
    )
    with pytest.raises(ValueError, match="non-routable or internal"):
        httpfetch.fetch("http://metadata.example/ocsp", timeout=1.0)


def test_http_caps_oversized_response(monkeypatch):
    """A response larger than the cap is rejected instead of read in full."""
    from certinspect import httpfetch

    monkeypatch.setattr(httpfetch, "_guard_fetch_host", lambda url: None)
    monkeypatch.setattr(httpfetch, "_MAX_HTTP_RESPONSE_BYTES", 10)

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self, amt=-1):
            return b"x" * amt

    monkeypatch.setattr(httpfetch._OPENER, "open", lambda *a, **k: _Resp())
    with pytest.raises(ValueError, match="exceeds the"):
        httpfetch.fetch("http://big.example/crl", timeout=1.0)


# --- SSRF guard on redirects -------------------------------------------------


@pytest.fixture
def serve():
    """Start throwaway HTTP servers on 127.0.0.1; ``serve(respond)`` -> base URL."""
    servers = []

    def _start(respond):
        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                respond(self)

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return f"http://127.0.0.1:{server.server_port}"

    yield _start
    for server in servers:
        server.shutdown()
        server.server_close()


def _redirect_to(location):
    def respond(handler):
        handler.send_response(302)
        handler.send_header("Location", location)
        handler.end_headers()

    return respond


def _body(payload, hits):
    def respond(handler):
        hits.append(handler.path)
        handler.send_response(200)
        handler.end_headers()
        handler.wfile.write(payload)

    return respond


def _guard_allowing(monkeypatch, *allowed_bases):
    """Treat URLs under ``allowed_bases`` as public; keep the real guard otherwise.

    Every test server listens on loopback, so this is how a test marks one of
    them as the "public" host a certificate URL points at. Returns the list of
    URLs the guard was asked about.
    """
    from certinspect import httpfetch

    real_guard = httpfetch._guard_fetch_host
    real_vetted = httpfetch._vetted_addresses
    checked = []

    def guard(url):
        checked.append(url)
        if not url.startswith(allowed_bases):
            real_guard(url)

    def vetted(host, port):
        if f"http://{host}:{port}" in allowed_bases:
            return [host]
        return real_vetted(host, port)

    monkeypatch.setattr(httpfetch, "_guard_fetch_host", guard)
    monkeypatch.setattr(httpfetch, "_vetted_addresses", vetted)
    return checked


def test_http_refuses_redirect_to_internal_address(monkeypatch, serve):
    from certinspect import httpfetch

    hits = []
    internal = serve(_body(b"SECRET", hits))
    public = serve(_redirect_to(f"{internal}/latest/meta-data/"))
    _guard_allowing(monkeypatch, public)

    with pytest.raises(ValueError, match="non-routable or internal"):
        httpfetch.fetch(f"{public}/crl", timeout=3.0)
    assert hits == []


def test_http_follows_redirect_between_allowed_hosts(monkeypatch, serve):
    from certinspect import httpfetch

    hits = []
    cdn = serve(_body(b"CRL-BYTES", hits))
    ca = serve(_redirect_to(f"{cdn}/ca.crl"))
    checked = _guard_allowing(monkeypatch, ca, cdn)

    assert httpfetch.fetch(f"{ca}/ca.crl", timeout=3.0) == b"CRL-BYTES"
    assert checked == [f"{ca}/ca.crl", f"{cdn}/ca.crl"]


def test_http_refuses_redirect_to_unsupported_scheme(monkeypatch, serve):
    from certinspect import httpfetch

    public = serve(_redirect_to("ftp://127.0.0.1:1/ca.crl"))
    _guard_allowing(monkeypatch, public)

    with pytest.raises(ValueError, match="unsupported URL scheme"):
        httpfetch.fetch(f"{public}/crl", timeout=3.0)


def test_http_caps_redirect_chain(monkeypatch, serve):
    from certinspect import httpfetch

    hits = []

    def respond(handler):
        hits.append(handler.path)
        step = int(handler.path.strip("/") or 0)
        _redirect_to(f"/{step + 1}")(handler)

    public = serve(respond)
    _guard_allowing(monkeypatch, public)

    with pytest.raises(OSError):
        httpfetch.fetch(f"{public}/0", timeout=3.0)
    assert len(hits) == httpfetch._MAX_REDIRECTS + 1


def test_http_connects_to_the_vetted_address_despite_dns_rebinding(monkeypatch, serve):
    """A name that resolves public for the check and loopback afterwards
    (DNS rebinding) must not reach the internal server."""
    import socket as _socket

    from certinspect import httpfetch

    hits = []
    internal = serve(_body(b"SECRET", hits))
    port = int(internal.rsplit(":", 1)[1])
    real_getaddrinfo = _socket.getaddrinfo
    answers = iter(["93.184.215.14", "127.0.0.1"])

    def rebinding_dns(host, *args, **kwargs):
        if host != "rebind.example":
            return real_getaddrinfo(host, *args, **kwargs)
        return _addrinfo(next(answers, "127.0.0.1"))

    monkeypatch.setattr(httpfetch.socket, "getaddrinfo", rebinding_dns)
    with pytest.raises(ValueError, match="non-routable or internal"):
        httpfetch.fetch(f"http://rebind.example:{port}/", timeout=3.0)
    assert hits == []


def test_http_fetch_has_a_total_deadline(monkeypatch, serve):
    """A server dripping its body below the per-read timeout is cut off."""
    from certinspect import httpfetch

    def respond(handler):
        handler.send_response(200)
        handler.send_header("Content-Length", "1000")
        handler.end_headers()
        try:
            for _ in range(200):
                handler.wfile.write(b"x")
                handler.wfile.flush()
                time.sleep(0.02)
        except OSError:
            pass

    public = serve(respond)
    _guard_allowing(monkeypatch, public)
    monkeypatch.setattr(httpfetch, "_FETCH_DEADLINE_SECONDS", 0.3)

    start = time.monotonic()
    with pytest.raises(TimeoutError, match="took longer than 0.3s"):
        httpfetch.fetch(f"{public}/crl", timeout=3.0)
    assert time.monotonic() - start < 2.0


def test_http_malformed_response_is_a_value_error(monkeypatch, serve):
    """A broken status line is a soft failure, not an unexpected exception."""
    from certinspect import httpfetch

    def respond(handler):
        handler.wfile.write(b"NOT-HTTP garbage")

    public = serve(respond)
    _guard_allowing(monkeypatch, public)
    with pytest.raises(ValueError, match="malformed HTTP response"):
        httpfetch.fetch(f"{public}/crl", timeout=3.0)


def _resolve_publicly(monkeypatch, name):
    """Make ``name`` pass the address check without real DNS."""
    import socket as _socket

    from certinspect import httpfetch

    real_getaddrinfo = _socket.getaddrinfo

    def fake(host, *args, **kwargs):
        if host == name:
            return _addrinfo("93.184.215.14")
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(httpfetch.socket, "getaddrinfo", fake)


def test_use_proxy_routes_fetches_through_the_proxy(monkeypatch, serve):
    from certinspect import httpfetch

    hits = []
    proxy = serve(_body(b"VIA-PROXY", hits))
    _resolve_publicly(monkeypatch, "ocsp.example")

    httpfetch.use_proxy(proxy)
    assert httpfetch.fetch("http://ocsp.example/ca.crl", timeout=3.0) == b"VIA-PROXY"
    assert hits == ["http://ocsp.example/ca.crl"]


def test_use_proxy_no_proxy_ignores_the_environment(monkeypatch, serve):
    from certinspect import httpfetch

    proxy_hits, direct_hits = [], []
    proxy = serve(_body(b"VIA-PROXY", proxy_hits))
    direct = serve(_body(b"DIRECT", direct_hits))
    _guard_allowing(monkeypatch, direct)
    monkeypatch.setenv("http_proxy", proxy)
    monkeypatch.delenv("no_proxy", raising=False)

    httpfetch.use_proxy(None, no_proxy=True)
    assert httpfetch.fetch(f"{direct}/ca.crl", timeout=3.0) == b"DIRECT"
    assert proxy_hits == []


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

    from certinspect import revocation

    now = datetime.now(timezone.utc)
    issuer_cert, leaf_cert, der = _signed_ocsp(
        ocsp.OCSPCertStatus.GOOD, now - timedelta(hours=1), now + timedelta(days=1)
    )
    monkeypatch.setattr(revocation, "fetch", lambda url, data=None, timeout=None: der)

    status, _ = revocation._check_ocsp(leaf_cert, issuer_cert, timeout=1.0)
    assert status == "GOOD"


def test_check_ocsp_soft_fails_on_stale_response(monkeypatch):
    """A GOOD response whose nextUpdate has passed must degrade to UNAVAILABLE,
    so a replayed stale answer cannot mask a later revocation."""
    from datetime import datetime, timedelta, timezone

    from cryptography.x509 import ocsp

    from certinspect import revocation

    now = datetime.now(timezone.utc)
    issuer_cert, leaf_cert, der = _signed_ocsp(
        ocsp.OCSPCertStatus.GOOD, now - timedelta(days=2), now - timedelta(days=1)
    )
    monkeypatch.setattr(revocation, "fetch", lambda url, data=None, timeout=None: der)

    status, detail = revocation._check_ocsp(leaf_cert, issuer_cert, timeout=1.0)
    assert status == "UNAVAILABLE"
    assert "stale" in detail


# --- revocation authenticity ------------------------------------------------

ISSUER_URL = "http://ca.example.com/issuer.der"


def _der(obj):
    from cryptography.hazmat.primitives import serialization

    return obj.public_bytes(serialization.Encoding.DER)


def _ca(name="Test CA"):
    """Return ``(cert, key)`` for a self-signed CA named ``name``."""
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    now = datetime.now(timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _leaf(issuer_cert, issuer_key, *, serial=4242, ca_issuers=False):
    """A leaf signed by ``issuer_key`` pointing at OCSP_URL and CRL_URL."""
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

    now = datetime.now(timezone.utc)
    access = [
        x509.AccessDescription(
            AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(OCSP_URL)
        )
    ]
    if ca_issuers:
        access.append(
            x509.AccessDescription(
                AuthorityInformationAccessOID.CA_ISSUERS,
                x509.UniformResourceIdentifier(ISSUER_URL),
            )
        )
    distribution_point = x509.DistributionPoint(
        full_name=[x509.UniformResourceIdentifier(CRL_URL)],
        relative_name=None,
        reasons=None,
        crl_issuer=None,
    )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")]))
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.AuthorityInformationAccess(access), critical=False)
        .add_extension(x509.CRLDistributionPoints([distribution_point]), critical=False)
        .sign(issuer_key, hashes.SHA256())
    )


def _ocsp_response(
    leaf, issuer, signer_cert, signer_key, *, status=None, embed=(), by_key=False
):
    """A fresh OCSP response about ``leaf``/``issuer``, signed by ``signer_key``."""
    from datetime import datetime, timedelta, timezone

    from cryptography.hazmat.primitives import hashes
    from cryptography.x509 import ocsp

    now = datetime.now(timezone.utc)
    status = status or ocsp.OCSPCertStatus.GOOD
    revoked = status == ocsp.OCSPCertStatus.REVOKED
    builder = (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=leaf,
            issuer=issuer,
            algorithm=hashes.SHA1(),
            cert_status=status,
            this_update=now - timedelta(hours=1),
            next_update=now + timedelta(days=1),
            revocation_time=now - timedelta(hours=2) if revoked else None,
            revocation_reason=None,
        )
        .responder_id(
            ocsp.OCSPResponderEncoding.HASH
            if by_key
            else ocsp.OCSPResponderEncoding.NAME,
            signer_cert,
        )
    )
    if embed:
        builder = builder.certificates(list(embed))
    return _der(builder.sign(signer_key, hashes.SHA256()))


def _serve(monkeypatch, bodies):
    """Answer revocation HTTP fetches from a url -> bytes mapping."""
    from certinspect import revocation

    def _fetch(url, data=None, timeout=None):
        if url not in bodies:
            raise OSError(f"no route to {url}")
        return bodies[url]

    monkeypatch.setattr(revocation, "fetch", _fetch)


def test_fetch_issuer_rejects_a_certificate_that_did_not_sign_the_leaf(monkeypatch):
    from certinspect import revocation

    ca, ca_key = _ca()
    mallory, _ = _ca()  # same name as the real CA, different key
    leaf = _leaf(ca, ca_key, ca_issuers=True)
    _serve(monkeypatch, {ISSUER_URL: _der(mallory)})

    assert revocation._fetch_issuer(leaf, 1.0) is None


def test_fetch_issuer_accepts_the_real_issuer(monkeypatch):
    from certinspect import revocation

    ca, ca_key = _ca()
    leaf = _leaf(ca, ca_key, ca_issuers=True)
    _serve(monkeypatch, {ISSUER_URL: _der(ca)})

    assert revocation._fetch_issuer(leaf, 1.0) == ca


def test_check_revocation_ignores_an_issuer_that_did_not_sign_the_leaf(monkeypatch):
    from certinspect import revocation

    ca, ca_key = _ca()
    mallory, mallory_key = _ca()
    leaf = _leaf(ca, ca_key)
    _serve(monkeypatch, {OCSP_URL: _ocsp_response(leaf, mallory, mallory, mallory_key)})

    status, _ = revocation.check_revocation(leaf, timeout=1.0, issuer=mallory)
    assert status == "UNAVAILABLE"


def _responder(issuer_cert, issuer_key, *, ocsp_signing=True):
    """Return ``(cert, key)`` for an OCSP responder delegated by ``issuer_key``."""
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.now(timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    builder = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OCSP Responder")])
        )
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
    )
    if ocsp_signing:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), critical=False
        )
    return builder.sign(issuer_key, hashes.SHA256()), key


def test_check_ocsp_accepts_a_response_signed_by_the_issuer_key_id(monkeypatch):
    from certinspect import revocation

    ca, ca_key = _ca()
    leaf = _leaf(ca, ca_key)
    _serve(monkeypatch, {OCSP_URL: _ocsp_response(leaf, ca, ca, ca_key, by_key=True)})

    assert revocation._check_ocsp(leaf, ca, timeout=1.0) == ("GOOD", None)


def test_check_ocsp_accepts_an_authorized_delegated_responder(monkeypatch):
    from certinspect import revocation

    ca, ca_key = _ca()
    leaf = _leaf(ca, ca_key)
    responder, responder_key = _responder(ca, ca_key)
    der = _ocsp_response(leaf, ca, responder, responder_key, embed=[responder])
    _serve(monkeypatch, {OCSP_URL: der})

    assert revocation._check_ocsp(leaf, ca, timeout=1.0) == ("GOOD", None)


def _mallory_signs(ca, ca_key, leaf):
    """Mallory's own CA, named like the real one, signs a GOOD for ``leaf``."""
    mallory, mallory_key = _ca()
    return _ocsp_response(leaf, ca, mallory, mallory_key)


def _other_certificate_good(ca, ca_key, leaf):
    """A genuine GOOD, signed by the CA, about another of its certificates."""
    return _ocsp_response(_leaf(ca, ca_key, serial=9999), ca, ca, ca_key)


def _forged_revoked(ca, ca_key, leaf):
    from cryptography.x509 import ocsp

    mallory, mallory_key = _ca()
    return _ocsp_response(
        leaf, ca, mallory, mallory_key, status=ocsp.OCSPCertStatus.REVOKED
    )


def _responder_without_ocsp_signing(ca, ca_key, leaf):
    responder, key = _responder(ca, ca_key, ocsp_signing=False)
    return _ocsp_response(leaf, ca, responder, key, embed=[responder])


def _responder_from_another_ca(ca, ca_key, leaf):
    mallory, mallory_key = _ca("Mallory CA")
    responder, key = _responder(mallory, mallory_key)
    return _ocsp_response(leaf, ca, responder, key, embed=[responder])


def _responder_not_embedded(ca, ca_key, leaf):
    responder, key = _responder(ca, ca_key)
    return _ocsp_response(leaf, ca, responder, key)


@pytest.mark.parametrize(
    "forge, reason",
    [
        (_mallory_signs, "signature"),
        (_other_certificate_good, "different certificate"),
        (_forged_revoked, "signature"),
        (_responder_without_ocsp_signing, "authorized responder"),
        (_responder_from_another_ca, "authorized responder"),
        (_responder_not_embedded, "authorized responder"),
    ],
)
def test_check_ocsp_rejects_an_unauthenticated_response(monkeypatch, forge, reason):
    from certinspect import revocation

    ca, ca_key = _ca()
    leaf = _leaf(ca, ca_key)
    _serve(monkeypatch, {OCSP_URL: forge(ca, ca_key, leaf)})

    status, detail = revocation._check_ocsp(leaf, ca, timeout=1.0)
    assert status == "UNAVAILABLE"
    assert reason in detail


def _crl(issuer_cert, signer_key, *, revoked=(), extensions=(), issuer_name=None):
    """A fresh DER CRL revoking ``revoked`` serials, with extra ``extensions``.

    ``extensions`` holds ``(extension, critical)`` pairs; ``issuer_name``
    overrides the CRL's issuer (defaults to ``issuer_cert``'s subject).
    """
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID

    now = datetime.now(timezone.utc)
    name = issuer_cert.subject
    if issuer_name is not None:
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)])
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(name)
        .last_update(now - timedelta(hours=1))
        .next_update(now + timedelta(days=1))
    )
    for serial in revoked:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(now - timedelta(hours=2))
            .build()
        )
    for extension, critical in extensions:
        builder = builder.add_extension(extension, critical=critical)
    return _der(builder.sign(signer_key, hashes.SHA256()))


def _idp(**flags):
    from cryptography import x509

    scope = {
        "full_name": None,
        "relative_name": None,
        "only_contains_user_certs": False,
        "only_contains_ca_certs": False,
        "only_some_reasons": None,
        "indirect_crl": False,
        "only_contains_attribute_certs": False,
    }
    return x509.IssuingDistributionPoint(**{**scope, **flags})


def _some_reasons():
    from cryptography import x509

    return _idp(only_some_reasons=frozenset({x509.ReasonFlags.key_compromise}))


def _delta():
    from cryptography import x509

    return x509.DeltaCRLIndicator(1)


def _unknown_critical():
    from cryptography import x509

    return x509.UnrecognizedExtension(
        x509.ObjectIdentifier("1.3.6.1.4.1.55555.1"), b"\x05\x00"
    )


def test_check_crl_needs_the_issuer_to_verify_the_signature(monkeypatch):
    from certinspect import revocation

    ca, ca_key = _ca()
    leaf = _leaf(ca, ca_key)
    _serve(monkeypatch, {CRL_URL: _crl(ca, ca_key)})

    status, detail = revocation._check_crl(leaf, None, timeout=1.0)
    assert status == "UNAVAILABLE"
    assert "issuer" in detail


def test_check_crl_ignores_a_crl_from_another_issuer_name(monkeypatch):
    from certinspect import revocation

    ca, ca_key = _ca()
    leaf = _leaf(ca, ca_key)
    _serve(monkeypatch, {CRL_URL: _crl(ca, ca_key, issuer_name="Other CA")})

    status, _ = revocation._check_crl(leaf, ca, timeout=1.0)
    assert status == "UNAVAILABLE"


@pytest.mark.parametrize(
    "extension",
    [
        lambda: _idp(only_contains_ca_certs=True),
        lambda: _idp(only_contains_attribute_certs=True),
        lambda: _idp(indirect_crl=True),
        _unknown_critical,
    ],
    ids=["ca-only", "attribute-only", "indirect", "unknown-critical"],
)
def test_check_crl_ignores_a_crl_that_cannot_cover_the_certificate(
    monkeypatch, extension
):
    from certinspect import revocation

    ca, ca_key = _ca()
    leaf = _leaf(ca, ca_key)
    _serve(
        monkeypatch,
        {CRL_URL: _crl(ca, ca_key, revoked=(4242,), extensions=[(extension(), True)])},
    )

    status, _ = revocation._check_crl(leaf, ca, timeout=1.0)
    assert status == "UNAVAILABLE"


@pytest.mark.parametrize("extension", [_some_reasons, _delta], ids=["reasons", "delta"])
@pytest.mark.parametrize(
    "revoked, expected", [((), "UNAVAILABLE"), ((4242,), "REVOKED")]
)
def test_check_crl_partial_crl_proves_revocation_but_not_good(
    monkeypatch, extension, revoked, expected
):
    from certinspect import revocation

    ca, ca_key = _ca()
    leaf = _leaf(ca, ca_key)
    _serve(
        monkeypatch,
        {CRL_URL: _crl(ca, ca_key, revoked=revoked, extensions=[(extension(), True)])},
    )

    status, _ = revocation._check_crl(leaf, ca, timeout=1.0)
    assert status == expected


def test_check_crl_accepts_a_user_certs_only_crl_for_a_leaf(monkeypatch):
    from certinspect import revocation

    ca, ca_key = _ca()
    leaf = _leaf(ca, ca_key)
    der = _crl(ca, ca_key, extensions=[(_idp(only_contains_user_certs=True), True)])
    _serve(monkeypatch, {CRL_URL: der})

    assert revocation._check_crl(leaf, ca, timeout=1.0) == ("GOOD", "via CRL")


# --- offline chain verification --------------------------------------------


def _pem(cert):
    from cryptography.hazmat.primitives import serialization

    return cert.public_bytes(serialization.Encoding.PEM)


def test_verify_chain_offline_trusts_a_bundled_chain(make_chain, tmp_path):
    from certinspect.fetch import verify_chain_offline

    leaf, intermediate, root = make_chain()
    ca = tmp_path / "root.pem"
    ca.write_bytes(_pem(root))

    trusted, reason, chain = verify_chain_offline(
        [leaf, intermediate, root], cafile=str(ca)
    )

    assert trusted is True
    assert reason is None
    assert chain[0].subject == leaf.subject
    assert len(chain) >= 2


def test_verify_chain_offline_rejects_an_untrusted_root(make_chain):
    from certinspect.fetch import verify_chain_offline

    leaf, intermediate, root = make_chain()
    # No cafile: the private test root is not in the system trust store.
    trusted, reason, chain = verify_chain_offline([leaf, intermediate, root])

    assert trusted is False
    assert reason
    assert chain == []


def test_verify_chain_offline_rejects_an_incomplete_chain(make_chain, tmp_path):
    from certinspect.fetch import verify_chain_offline

    leaf, _intermediate, root = make_chain()
    ca = tmp_path / "root.pem"
    ca.write_bytes(_pem(root))

    # Leaf only, missing the intermediate: no path can be built to the root.
    trusted, reason, chain = verify_chain_offline([leaf], cafile=str(ca))

    assert trusted is False
    assert reason
    assert chain == []


def test_verify_chain_offline_needs_a_name(make_cert):
    from certinspect.fetch import verify_chain_offline
    from certinspect.parser import load_certificates

    # No SAN and a Common Name that is not a valid hostname: nothing to anchor.
    certs = load_certificates(make_cert(san=None, common_name="Internal Root"))
    trusted, reason, chain = verify_chain_offline(certs)

    assert trusted is False
    assert "name" in reason
    assert chain == []


@pytest.mark.parametrize("san", [("*.example.com", "example.com"), ("*.example.com",)])
def test_verify_chain_offline_trusts_a_wildcard_leaf(make_chain, tmp_path, san):
    from certinspect.fetch import verify_chain_offline

    leaf, intermediate, root = make_chain(leaf_cn="example.com", leaf_san=san)
    ca = tmp_path / "root.pem"
    ca.write_bytes(_pem(root))

    trusted, reason, _ = verify_chain_offline([leaf, intermediate], cafile=str(ca))

    assert trusted is True, reason


def test_verify_chain_offline_empty_bundle():
    from certinspect.fetch import verify_chain_offline

    trusted, reason, chain = verify_chain_offline([])

    assert trusted is False
    assert reason
    assert chain == []
