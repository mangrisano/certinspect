"""Retrieve the certificate from a TLS server.

Connect to a host:port over TLS and obtain the server certificate in DER
format (bytes) together with basic connection info (negotiated TLS version
and cipher).

Hostname checking and verification are disabled on purpose: this tool must
be able to inspect expired or self-signed certificates without the
connection failing. Validity is computed later in parser.py.
"""

import base64
import ipaddress
import socket
import ssl
import time
import urllib.request
import warnings
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp, verification
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID


# Standard plaintext ports for the STARTTLS-capable protocols, used as the
# default port when --port is left unset.
STARTTLS_PORTS = {"smtp": 587, "imap": 143, "pop3": 110, "ftp": 21}

# Cap the size of any certificate-supplied HTTP response (OCSP/CRL/CA-Issuer)
# so a malicious certificate cannot point us at an unbounded download and
# exhaust memory. Real-world CRLs stay comfortably below this.
_MAX_HTTP_RESPONSE_BYTES = 16 * 1024 * 1024

# Clock-skew tolerance when judging whether an OCSP response is still fresh.
_OCSP_CLOCK_SKEW = timedelta(minutes=5)


def _is_blocked_fetch_address(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """Return True for addresses a certificate-supplied URL must not reach.

    Loopback, link-local (which covers the cloud metadata endpoint
    ``169.254.169.254``), unspecified, multicast and reserved ranges are
    refused. Private RFC1918 ranges are deliberately allowed so revocation
    still works behind an internal PKI.
    """
    return (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_unspecified
        or ip.is_multicast
        or ip.is_reserved
    )


def _guard_fetch_host(url: str) -> None:
    """Refuse to fetch a certificate-supplied URL pointing at an internal host.

    OCSP, CRL and CA-Issuer URLs come from the inspected certificate, i.e. from
    untrusted input; following them blindly would turn certinspect into an SSRF
    primitive able to reach the cloud metadata service or a port on localhost.
    The host is resolved and every returned address checked. The guard is
    best-effort (the HTTP client resolves DNS again, so a rebinding attacker
    could still race it) but closes the obvious vectors. Raises ValueError when
    the target is not allowed, which the callers already treat as a soft-fail.
    """
    host = urlsplit(url).hostname
    if not host:
        raise ValueError(f"URL has no host: {url}")
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except OSError as err:
        raise ValueError(f"could not resolve {host}: {err}") from err
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if _is_blocked_fetch_address(ip):
            raise ValueError(
                f"refusing to fetch {url}: {ip} is a non-routable or internal address"
            )


def _read_connect_response(sock: socket.socket) -> bytes:
    """Read an HTTP CONNECT response up to the end of its header block."""
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(256)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 65536:
            break
    return bytes(buf)


def _resolve_proxy(host: str, proxy: str | None, no_proxy: bool) -> str | None:
    """Return the proxy URL to use for ``host``, or None for a direct link.

    An explicit ``proxy`` wins. ``no_proxy`` forces a direct connection. With
    neither, fall back to the environment's HTTPS/HTTP proxy (``HTTPS_PROXY``
    and friends, plus the system settings on macOS/Windows), honouring
    ``NO_PROXY`` so excluded hosts stay direct — the same behaviour as curl.
    """
    if no_proxy:
        return None
    if proxy:
        return proxy
    proxies = urllib.request.getproxies()
    candidate = proxies.get("https") or proxies.get("http")
    if not candidate:
        return None
    if urllib.request.proxy_bypass(host):
        return None
    return candidate


def _open_socket(
    host: str,
    port: int,
    connect_timeout: float,
    read_timeout: float,
    proxy: str | None = None,
) -> socket.socket:
    """Open a TCP socket to ``host:port``, directly or via an HTTP proxy.

    The socket is opened with ``connect_timeout`` and then switched to
    ``read_timeout`` for the TLS handshake and subsequent reads.

    When ``proxy`` is set (e.g. ``http://user:pass@proxy:8080``) the connection
    is tunnelled through the proxy with the HTTP ``CONNECT`` method, so a host
    behind a corporate/cloud egress proxy can still be reached. Raises
    ValueError if the proxy refuses the tunnel.
    """
    if not proxy:
        sock = socket.create_connection((host, port), timeout=connect_timeout)
        sock.settimeout(read_timeout)
        return sock

    parts = urlsplit(proxy if "://" in proxy else f"//{proxy}")
    sock = socket.create_connection(
        (parts.hostname, parts.port or 8080), timeout=connect_timeout
    )
    try:
        request = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
        if parts.username is not None:
            creds = f"{parts.username}:{parts.password or ''}".encode()
            token = base64.b64encode(creds).decode("ascii")
            request += f"Proxy-Authorization: Basic {token}\r\n"
        request += "\r\n"
        sock.sendall(request.encode("ascii"))
        status_line = _read_connect_response(sock).split(b"\r\n", 1)[0]
        fields = status_line.split(None, 2)
        if len(fields) < 2 or fields[1] != b"200":
            raise ValueError(
                f"proxy CONNECT to {host}:{port} failed: "
                f"{status_line.decode('latin-1', 'replace').strip()}"
            )
    except Exception:
        sock.close()
        raise
    sock.settimeout(read_timeout)
    return sock


_RETRY_BACKOFF_SECONDS = 0.5


def retry_network(call, retries: int):
    """Run ``call`` again on transient network errors, up to ``retries`` times.

    Only connection-level failures (timeouts, refused/reset connections, DNS
    errors) are retried; a completed handshake that yields a result is returned
    as-is. Re-raises the last error once the retries are exhausted.
    """
    for remaining in range(retries, -1, -1):
        try:
            return call()
        except (TimeoutError, ConnectionError, socket.gaierror):
            if remaining == 0:
                raise
            time.sleep(_RETRY_BACKOFF_SECONDS)


def _split_timeout(timeout: float | tuple[float, float]) -> tuple[float, float]:
    """Return (connect, read) timeouts from a float or a (connect, read) tuple."""
    if isinstance(timeout, tuple):
        return timeout
    return timeout, timeout


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
    host: str,
    port: int = 443,
    timeout: float = 5.0,
    starttls: str | None = None,
    servername: str | None = None,
    client_cert: str | None = None,
    client_key: str | None = None,
    proxy: str | None = None,
    no_proxy: bool = False,
) -> tuple[bytes, dict]:
    """Return the server certificate (DER bytes) and connection info.

    The connection info is a dict with the negotiated ``tls_version``, the
    ``cipher`` suite name, and the ``chain`` presented by the server (leaf
    first) when the interpreter exposes it (Python 3.13+), otherwise [].

    When ``starttls`` is set (smtp, imap, pop3 or ftp) the plaintext protocol
    is upgraded to TLS before the certificate is read.

    ``servername`` overrides the SNI hostname sent in the TLS handshake; it
    defaults to ``host``. Use it to reach a specific backend by IP while still
    presenting the virtual hostname a load balancer routes on.

    ``client_cert``/``client_key`` present a client certificate for mutual TLS
    (mTLS) endpoints. ``proxy`` tunnels the connection through an HTTP CONNECT
    proxy (e.g. ``http://proxy:8080``); with no explicit proxy the environment
    (``HTTPS_PROXY``/``NO_PROXY``) is honoured unless ``no_proxy`` is set.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if client_cert:
        context.load_cert_chain(certfile=client_cert, keyfile=client_key)
    connect_timeout, read_timeout = _split_timeout(timeout)
    resolved_proxy = _resolve_proxy(host, proxy, no_proxy)
    with _open_socket(
        host, port, connect_timeout, read_timeout, resolved_proxy
    ) as sock:
        if starttls:
            _negotiate_starttls(sock, starttls)
        with context.wrap_socket(sock, server_hostname=servername or host) as ssock:
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
    servername: str | None = None,
    client_cert: str | None = None,
    client_key: str | None = None,
    proxy: str | None = None,
    no_proxy: bool = False,
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

    ``servername`` overrides the SNI hostname sent in the handshake (and thus
    the name the certificate is validated against); it defaults to ``host``.

    ``client_cert``/``client_key`` present a client certificate for mutual TLS,
    and ``proxy`` tunnels the handshake through an HTTP CONNECT proxy (with the
    environment's proxy honoured by default unless ``no_proxy`` is set).
    """
    if cafile or capath:
        context = ssl.create_default_context(cafile=cafile, capath=capath)
    else:
        context = ssl.create_default_context()
    # Verify chain trust only; the hostname is reported separately as hostname_match.
    context.check_hostname = False
    if client_cert:
        context.load_cert_chain(certfile=client_cert, keyfile=client_key)
    connect_timeout, read_timeout = _split_timeout(timeout)
    resolved_proxy = _resolve_proxy(host, proxy, no_proxy)
    try:
        with _open_socket(
            host, port, connect_timeout, read_timeout, resolved_proxy
        ) as sock:
            if starttls:
                _negotiate_starttls(sock, starttls)
            with context.wrap_socket(sock, server_hostname=servername or host) as ssock:
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


def _trust_anchors(cafile: str | None, capath: str | None) -> list[x509.Certificate]:
    """Return the trusted root certificates for offline verification.

    Mirror the trust decision of the live ``verify_chain``: use ``cafile`` /
    ``capath`` when given (an internal/private PKI), otherwise the system trust
    store. A root the current OpenSSL/cryptography cannot parse (e.g. a legacy
    certificate with a non-positive serial) is skipped rather than aborting.
    """
    if cafile or capath:
        context = ssl.create_default_context(cafile=cafile, capath=capath)
    else:
        context = ssl.create_default_context()
    anchors: list[x509.Certificate] = []
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for der in context.get_ca_certs(binary_form=True):
            try:
                anchors.append(x509.load_der_x509_certificate(der))
            except ValueError:
                continue
    return anchors


def _offline_verification_subject(
    leaf: x509.Certificate,
) -> "verification.Subject | None":
    """Return a verification subject (DNS/IP) taken from the leaf itself.

    Chain trust is name-independent here — hostname matching is reported
    separately — so the leaf's own first SAN entry (falling back to its Common
    Name) is used. That turns the verifier's mandatory name check into a no-op
    while its signature, validity and trust-anchor checks still run. Returns
    None when the leaf carries no usable name.
    """
    try:
        san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        san = None
    if san is not None:
        dns = san.get_values_for_type(x509.DNSName)
        if dns:
            return verification.DNSName(dns[0])
        ips = san.get_values_for_type(x509.IPAddress)
        if ips:
            return verification.IPAddress(ips[0])
    cn = leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn:
        try:
            return verification.DNSName(cn[0].value)
        except ValueError:
            return None
    return None


def verify_chain_offline(
    certs: list[x509.Certificate],
    *,
    cafile: str | None = None,
    capath: str | None = None,
) -> tuple[bool, str | None, list[x509.Certificate]]:
    """Verify a certificate chain held in a local bundle, without a network.

    ``certs`` is the bundle in file order (leaf first, then its intermediates
    and — optionally — the root). The leaf is validated against the system
    trust store (or ``cafile``/``capath`` for an internal PKI) using the other
    certificates as untrusted intermediates, exactly like ``openssl verify``:
    signatures, validity windows and basic constraints are all checked. Return
    ``(trusted, reason, chain)`` where ``chain`` is the built path (leaf first)
    on success and ``reason`` is the failure message otherwise.
    """
    if not certs:
        return False, "there is no certificate to verify", []
    leaf, intermediates = certs[0], certs[1:]
    subject = _offline_verification_subject(leaf)
    if subject is None:
        return (
            False,
            "the certificate has no DNS name or IP address to anchor verification",
            [],
        )
    anchors = _trust_anchors(cafile, capath)
    if not anchors:
        return False, "no trusted CA certificates were available", []
    store = verification.Store(anchors)
    try:
        verifier = (
            verification.PolicyBuilder().store(store).build_server_verifier(subject)
        )
    except ValueError:
        return False, "the certificate has no valid name to anchor verification", []
    try:
        verified = verifier.verify(leaf, intermediates)
    except verification.VerificationError as err:
        return False, str(err), []
    return True, None, list(verified)


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
    certificate's own AIA/CRL extensions, i.e. from untrusted input, so the
    target host is screened against internal/non-routable addresses and the
    response size is capped. A POST is used when ``data`` is given.
    """
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError(f"unsupported URL scheme: {url}")
    _guard_fetch_host(url)
    headers = {"Content-Type": "application/ocsp-request"} if data else {}
    request = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        body = response.read(_MAX_HTTP_RESPONSE_BYTES + 1)
    if len(body) > _MAX_HTTP_RESPONSE_BYTES:
        raise ValueError(
            f"response from {url} exceeds the {_MAX_HTTP_RESPONSE_BYTES}-byte limit"
        )
    return body


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


def _ocsp_response_stale(response: ocsp.OCSPResponse) -> str | None:
    """Return a reason when the OCSP response is outside its validity window.

    A response whose ``nextUpdate`` is already in the past (or whose
    ``thisUpdate`` lies in the future) may be a replayed or stale answer and
    must not back a trusted GOOD verdict; a small clock-skew tolerance is
    allowed. Missing timestamps or parse errors return None ("cannot tell"),
    preserving the browser-like soft-fail behaviour.
    """
    now = datetime.now(timezone.utc)
    try:
        this_update = response.this_update_utc
        next_update = response.next_update_utc
    except (ValueError, AttributeError):
        return None
    if this_update is not None and this_update - _OCSP_CLOCK_SKEW > now:
        return f"OCSP response not yet valid (thisUpdate {this_update})"
    if next_update is not None and next_update + _OCSP_CLOCK_SKEW < now:
        return f"OCSP response is stale (nextUpdate {next_update})"
    return None


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

    # Parsing must soft-fail too: some responders (e.g. DigiCert/GitHub) return
    # a BasicOCSPResponse whose signatureAlgorithm the strict ASN.1 parser
    # rejects with a ValueError. A malformed response must not abort the whole
    # inspection — degrade to UNAVAILABLE and let the CRL fallback take over.
    try:
        response = ocsp.load_der_ocsp_response(raw)
        if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            return (
                "UNAVAILABLE",
                f"OCSP response status: {response.response_status.name}",
            )
        status = response.certificate_status
    except ValueError as err:
        return "UNAVAILABLE", f"OCSP response could not be parsed: {err}"

    if status == ocsp.OCSPCertStatus.GOOD:
        stale = _ocsp_response_stale(response)
        if stale is not None:
            return "UNAVAILABLE", stale
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


def _crl_stale(crl: x509.CertificateRevocationList) -> str | None:
    """Return a reason when a CRL is outside its validity window."""
    now = datetime.now(timezone.utc)
    try:
        last_update = crl.last_update_utc
        next_update = crl.next_update_utc
    except (ValueError, AttributeError):
        return None
    if last_update is not None and last_update - _OCSP_CLOCK_SKEW > now:
        return f"CRL is not yet valid (lastUpdate {last_update})"
    if next_update is not None and next_update + _OCSP_CLOCK_SKEW < now:
        return f"CRL is stale (nextUpdate {next_update})"
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
        stale = _crl_stale(crl)
        if stale is not None:
            return "UNAVAILABLE", stale
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
