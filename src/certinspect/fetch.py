"""Retrieve the certificate from a TLS server.

Connect to a host:port over TLS and obtain the server certificate in DER
format (bytes) together with basic connection info (negotiated TLS version
and cipher).

Hostname checking and verification are disabled on purpose: this tool must
be able to inspect expired or self-signed certificates without the
connection failing. Validity is computed later in parser.py.
"""

import socket
import ssl
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID


# Standard plaintext ports for the STARTTLS-capable protocols, used as the
# default port when --port is left unset.
STARTTLS_PORTS = {"smtp": 587, "imap": 143, "pop3": 110, "ftp": 21}


def _readline(sock: socket.socket) -> bytes:
    """Read one line (up to and including ``\\n``) from a plaintext socket.

    Reads a byte at a time so we never consume data past the STARTTLS
    negotiation: the server stays silent until we begin the TLS handshake.
    """
    buf = bytearray()
    while not buf.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


def _read_reply(sock: socket.socket) -> bytes:
    """Read a possibly multiline SMTP/FTP reply and return its final line.

    Continuation lines use ``-`` as the fourth character (e.g. ``250-``); the
    last line uses a space (``250 ``).
    """
    while True:
        line = _readline(sock)
        if len(line) < 4 or line[3:4] != b"-":
            return line


def _expect(line: bytes, prefix: bytes) -> None:
    """Raise when a STARTTLS reply does not start with the expected code."""
    if not line.startswith(prefix):
        raise ValueError(f"unexpected STARTTLS reply: {line!r}")


def _negotiate_starttls(sock: socket.socket, protocol: str) -> None:
    """Run the plaintext STARTTLS handshake for ``protocol`` on ``sock``.

    Supports the line-based protocols smtp, imap, pop3 and ftp. On return the
    socket is ready to be wrapped in TLS. Raises ValueError if the server does
    not agree to upgrade.
    """
    proto = protocol.lower()
    if proto == "smtp":
        _expect(_read_reply(sock), b"220")
        sock.sendall(b"EHLO certinspect\r\n")
        _expect(_read_reply(sock), b"250")
        sock.sendall(b"STARTTLS\r\n")
        _expect(_read_reply(sock), b"220")
    elif proto == "ftp":
        _expect(_read_reply(sock), b"220")
        sock.sendall(b"AUTH TLS\r\n")
        _expect(_read_reply(sock), b"234")
    elif proto == "pop3":
        _expect(_readline(sock), b"+OK")
        sock.sendall(b"STLS\r\n")
        _expect(_readline(sock), b"+OK")
    elif proto == "imap":
        _expect(_readline(sock), b"* OK")
        sock.sendall(b"a001 STARTTLS\r\n")
        while True:
            line = _readline(sock)
            if not line:
                raise ValueError("connection closed during STARTTLS")
            if line.startswith(b"a001 "):
                _expect(line, b"a001 OK")
                break
    else:
        raise ValueError(f"unsupported STARTTLS protocol: {protocol}")


def get_server_cert(
    host: str, port: int = 443, timeout: float = 5.0, starttls: str | None = None
) -> tuple[bytes, dict]:
    """Return the server certificate (DER bytes) and connection info.

    The connection info is a dict with the negotiated ``tls_version``, the
    ``cipher`` suite name, and the ``chain`` presented by the server (leaf
    first) when the interpreter exposes it (Python 3.13+), otherwise [].

    When ``starttls`` is set (smtp, imap, pop3 or ftp) the plaintext protocol
    is upgraded to TLS before the certificate is read.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        if starttls:
            _negotiate_starttls(sock, starttls)
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
            cipher = ssock.cipher()
            conn = {
                "tls_version": ssock.version(),
                "cipher": cipher[0] if cipher else None,
                "chain": _presented_chain(ssock),
            }
            return der, conn


def _presented_chain(ssock: ssl.SSLSocket) -> list[x509.Certificate]:
    """Return the chain presented by the server (leaf first), or [].

    ``SSLSocket.get_unverified_chain`` exists from Python 3.13 and returns the
    certificates exactly as sent by the server (regardless of trust), which is
    what we want for inspection. Older interpreters return an empty list.
    """
    getter = getattr(ssock, "get_unverified_chain", None)
    if getter is None:
        return []
    try:
        return [x509.load_der_x509_certificate(der) for der in getter()]
    except (TypeError, ValueError, ssl.SSLError):
        return []


def verify_chain(
    host: str,
    port: int = 443,
    timeout: float = 5.0,
    starttls: str | None = None,
    cafile: str | None = None,
    capath: str | None = None,
) -> tuple[bool, str | None, list[x509.Certificate]]:
    """Check whether the server's certificate chain is trusted.

    Open a fully verified TLS handshake (system trust store, hostname check)
    as a browser would. Return ``(trusted, reason, chain)`` where ``chain`` is
    the verified certificate chain (leaf first) when the interpreter exposes
    it (Python 3.13+) and verification succeeds, otherwise an empty list.
    ``reason`` is None on success or the verification message on failure.
    Network-level failures are left to propagate. When ``starttls`` is set the
    plaintext protocol is upgraded to TLS before the handshake.

    When ``cafile`` and/or ``capath`` are given, the chain is verified against
    that CA bundle/directory instead of the system trust store, which is what
    you want behind an internal/private PKI.
    """
    if cafile or capath:
        context = ssl.create_default_context(cafile=cafile, capath=capath)
    else:
        context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            if starttls:
                _negotiate_starttls(sock, starttls)
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                return True, None, _verified_chain(ssock)
    except ssl.SSLCertVerificationError as err:
        return False, err.verify_message or str(err), []


def _verified_chain(ssock: ssl.SSLSocket) -> list[x509.Certificate]:
    """Return the verified chain (leaf first), or [] when unavailable.

    ``SSLSocket.get_verified_chain`` exists from Python 3.13 and yields the
    chain as DER-encoded bytes. Older interpreters return an empty list.
    """
    getter = getattr(ssock, "get_verified_chain", None)
    if getter is None:
        return []
    try:
        return [x509.load_der_x509_certificate(der) for der in getter()]
    except (TypeError, ValueError, ssl.SSLError):
        return []


def _aia_urls(cert: x509.Certificate) -> tuple[list[str], list[str]]:
    """Return (ocsp_urls, ca_issuer_urls) from the certificate's AIA extension.

    Both lists are empty when the Authority Information Access extension is
    absent.
    """
    try:
        aia = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        ).value
    except x509.ExtensionNotFound:
        return [], []

    ocsp_urls: list[str] = []
    issuer_urls: list[str] = []
    for desc in aia:
        location = desc.access_location.value
        if desc.access_method == AuthorityInformationAccessOID.OCSP:
            ocsp_urls.append(location)
        elif desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
            issuer_urls.append(location)
    return ocsp_urls, issuer_urls


def _http(url: str, *, data: bytes | None = None, timeout: float) -> bytes:
    """Perform a minimal HTTP(S) GET/POST and return the response body.

    Only ``http`` and ``https`` URLs are accepted; the URLs come from the
    certificate's own AIA extension. A POST is used when ``data`` is given.
    """
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError(f"unsupported URL scheme: {url}")
    headers = {"Content-Type": "application/ocsp-request"} if data else {}
    request = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        return response.read()


def _fetch_issuer(cert: x509.Certificate, timeout: float) -> x509.Certificate | None:
    """Download the issuer certificate via the AIA "CA Issuers" URL.

    Return None when no usable issuer can be retrieved.
    """
    _, issuer_urls = _aia_urls(cert)
    for url in issuer_urls:
        try:
            return x509.load_der_x509_certificate(_http(url, timeout=timeout))
        except (OSError, ValueError):
            continue
    return None


def _crl_urls(cert: x509.Certificate) -> list[str]:
    """Return the HTTP(S) CRL distribution-point URLs from the certificate.

    Only ``http``/``https`` distribution points are returned (LDAP and other
    schemes are skipped). The list is empty when the CRLDistributionPoints
    extension is absent or carries no usable URL.
    """
    try:
        dps = cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        ).value
    except x509.ExtensionNotFound:
        return []

    urls: list[str] = []
    for dp in dps:
        for name in dp.full_name or []:
            value = getattr(name, "value", None)
            if isinstance(value, str) and value.lower().startswith(
                ("http://", "https://")
            ):
                urls.append(value)
    return urls


def _check_ocsp(
    cert: x509.Certificate,
    issuer: x509.Certificate | None,
    timeout: float,
) -> tuple[str, str | None]:
    """Check revocation via OCSP. See ``check_revocation`` for the status set."""
    ocsp_urls, _ = _aia_urls(cert)
    if not ocsp_urls:
        return "UNAVAILABLE", "no OCSP responder in AIA extension"
    if issuer is None:
        return "UNAVAILABLE", "issuer certificate could not be retrieved"

    # OCSP CertID conventionally uses SHA-1 for the issuer name/key hashes;
    # many responders reject other digests.
    builder = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA1())
    der_request = builder.build().public_bytes(serialization.Encoding.DER)

    try:
        raw = _http(ocsp_urls[0], data=der_request, timeout=timeout)
    except (OSError, ValueError) as err:
        return "UNAVAILABLE", f"OCSP request failed: {err}"

    response = ocsp.load_der_ocsp_response(raw)
    if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return "UNAVAILABLE", f"OCSP response status: {response.response_status.name}"

    status = response.certificate_status
    if status == ocsp.OCSPCertStatus.GOOD:
        return "GOOD", None
    if status == ocsp.OCSPCertStatus.REVOKED:
        when = getattr(response, "revocation_time_utc", None)
        return "REVOKED", f"revoked at {when}" if when else "revoked"
    return "UNKNOWN", "responder does not know this certificate"


def _load_crl(raw: bytes) -> x509.CertificateRevocationList | None:
    """Parse a CRL from DER or PEM bytes, or return None when neither works."""
    try:
        return x509.load_der_x509_crl(raw)
    except ValueError:
        try:
            return x509.load_pem_x509_crl(raw)
        except ValueError:
            return None


def _check_crl(
    cert: x509.Certificate,
    issuer: x509.Certificate | None,
    timeout: float,
) -> tuple[str, str | None]:
    """Check revocation via the certificate's CRL distribution points.

    Download each CRL in turn and look up the certificate's serial number.
    When ``issuer`` is known the CRL signature is verified and a CRL that
    fails the check is skipped. The first CRL that yields a verdict wins;
    otherwise the status is ``"UNAVAILABLE"`` (soft-fail).
    """
    urls = _crl_urls(cert)
    if not urls:
        return "UNAVAILABLE", "no CRL distribution point in extension"

    for url in urls:
        try:
            raw = _http(url, timeout=timeout)
        except (OSError, ValueError):
            continue
        crl = _load_crl(raw)
        if crl is None:
            continue
        if issuer is not None and not crl.is_signature_valid(issuer.public_key()):
            continue

        revoked = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
        if revoked is not None:
            when = getattr(revoked, "revocation_date_utc", None)
            detail = f"revoked at {when}" if when else "revoked"
            return "REVOKED", f"{detail} (via CRL)"
        return "GOOD", "via CRL"

    return "UNAVAILABLE", "CRL could not be retrieved"


def check_revocation(
    cert: x509.Certificate,
    timeout: float = 5.0,
    issuer: x509.Certificate | None = None,
) -> tuple[str, str | None]:
    """Check the certificate's revocation status via OCSP, then CRL.

    Return ``(status, detail)`` where status is one of:

    * ``"GOOD"`` — the certificate is confirmed valid.
    * ``"REVOKED"`` — the certificate is confirmed revoked.
    * ``"UNKNOWN"`` — the OCSP responder does not know this certificate.
    * ``"UNAVAILABLE"`` — neither OCSP nor CRL gave an answer (soft-fail,
      like a browser).

    OCSP is tried first. When it soft-fails (no responder, issuer unavailable,
    network or responder error) the certificate's CRL distribution points are
    queried as a fallback. ``detail`` carries extra context (e.g. the
    revocation time, or which source answered) when useful.

    When ``issuer`` is provided (e.g. from the verified TLS chain) it is used
    directly; otherwise the issuer is downloaded via the AIA "CA Issuers" URL.
    """
    if issuer is None:
        issuer = _fetch_issuer(cert, timeout)

    status, detail = _check_ocsp(cert, issuer, timeout)
    if status != "UNAVAILABLE":
        return status, detail

    crl_status, crl_detail = _check_crl(cert, issuer, timeout)
    if crl_status != "UNAVAILABLE":
        return crl_status, crl_detail

    # Both soft-failed: report the OCSP reason, which is usually the more
    # informative of the two.
    return status, detail
