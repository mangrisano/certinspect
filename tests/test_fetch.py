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
