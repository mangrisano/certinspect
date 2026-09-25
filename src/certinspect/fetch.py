"""Retrieve the certificate from a TLS server.

Connect to a host:port over TLS and obtain the server certificate in DER
format (bytes) together with basic connection info (negotiated TLS version
and cipher).

Hostname checking and verification are disabled on purpose: this tool must
be able to inspect expired or self-signed certificates without the
connection failing. Validity is computed later in parser.py.
"""

import base64
import socket
import ssl
import time
import urllib.request
import warnings
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.x509 import verification
from cryptography.x509.oid import NameOID


# Standard plaintext ports for the STARTTLS-capable protocols, used as the
# default port when --port is left unset.
STARTTLS_PORTS = {"smtp": 587, "imap": 143, "pop3": 110, "ftp": 21}


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


# Bounds on what a (possibly hostile) server may send during STARTTLS. RFC 5321
# caps an SMTP reply line at 512 bytes and a real EHLO reply has ~10 lines.
_MAX_STARTTLS_LINE_BYTES = 8192
_MAX_STARTTLS_REPLY_LINES = 100


def _readline(sock: socket.socket) -> bytes:
    """Read one line (up to and including ``\\n``) from a plaintext socket.

    Reads a byte at a time so we never consume data past the STARTTLS
    negotiation: the server stays silent until we begin the TLS handshake.
    Raises ValueError when the line exceeds ``_MAX_STARTTLS_LINE_BYTES``.
    """
    buf = bytearray()
    while not buf.endswith(b"\n"):
        if len(buf) >= _MAX_STARTTLS_LINE_BYTES:
            raise ValueError("STARTTLS reply line too long")
        chunk = sock.recv(1)
        if not chunk:
            break
        buf += chunk
    return bytes(buf)


def _read_reply(sock: socket.socket) -> bytes:
    """Read a possibly multiline SMTP/FTP reply and return its final line.

    Continuation lines use ``-`` as the fourth character (e.g. ``250-``); the
    last line uses a space (``250 ``). Raises ValueError when the reply has
    more than ``_MAX_STARTTLS_REPLY_LINES`` lines.
    """
    for _ in range(_MAX_STARTTLS_REPLY_LINES):
        line = _readline(sock)
        if len(line) < 4 or line[3:4] != b"-":
            return line
    raise ValueError("STARTTLS reply has too many lines")


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
        for _ in range(_MAX_STARTTLS_REPLY_LINES):
            line = _readline(sock)
            if not line:
                raise ValueError("connection closed during STARTTLS")
            if line.startswith(b"a001 "):
                _expect(line, b"a001 OK")
                return
        raise ValueError("STARTTLS reply has too many lines")
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
                "chain": _chain(ssock, "get_unverified_chain"),
            }
            return der, conn


def _chain(ssock: ssl.SSLSocket, method: str) -> list[x509.Certificate]:
    """Return the chain from ``ssock.<method>()`` (leaf first), or [].

    ``get_unverified_chain`` (the certificates exactly as sent, regardless of
    trust) and ``get_verified_chain`` exist from Python 3.13; older
    interpreters, or a chain that cannot be parsed, yield an empty list.
    """
    getter = getattr(ssock, method, None)
    if getter is None:
        return []
    try:
        return [x509.load_der_x509_certificate(der) for der in getter()]
    except (TypeError, ValueError, ssl.SSLError):
        return []


def _trust_context(cafile: str | None, capath: str | None) -> ssl.SSLContext:
    """Return a verifying context trusting ``cafile``/``capath`` or the system store."""
    if cafile or capath:
        return ssl.create_default_context(cafile=cafile, capath=capath)
    return ssl.create_default_context()


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
    context = _trust_context(cafile, capath)
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
                return True, None, _chain(ssock, "get_verified_chain")
    except ssl.SSLCertVerificationError as err:
        return False, err.verify_message or str(err), []


def _trust_anchors(cafile: str | None, capath: str | None) -> list[x509.Certificate]:
    """Return the trusted root certificates for offline verification.

    Mirror the trust decision of the live ``verify_chain``: use ``cafile`` /
    ``capath`` when given (an internal/private PKI), otherwise the system trust
    store. A root the current OpenSSL/cryptography cannot parse (e.g. a legacy
    certificate with a non-positive serial) is skipped rather than aborting.
    """
    context = _trust_context(cafile, capath)
    anchors: list[x509.Certificate] = []
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for der in context.get_ca_certs(binary_form=True):
            try:
                anchors.append(x509.load_der_x509_certificate(der))
            except ValueError:
                continue
    return anchors


# Stands in for the '*' of a wildcard SAN so the verifier gets a concrete host.
_WILDCARD_PROBE_LABEL = "certinspect-probe"


def _concrete_dns_name(names: list[str]) -> str:
    """Return the first non-wildcard name, else the first one made concrete.

    The verifier rejects a pattern such as ``*.example.com`` as the name to
    check, so a wildcard becomes ``certinspect-probe.example.com``, which the
    certificate's own wildcard SAN covers.
    """
    for name in names:
        if "*" not in name:
            return name
    first = names[0]
    if first.startswith("*."):
        return _WILDCARD_PROBE_LABEL + first[1:]
    return first


def _offline_verification_subject(
    leaf: x509.Certificate,
) -> "verification.Subject | None":
    """Return a verification subject (DNS/IP) taken from the leaf itself.

    Chain trust is name-independent here — hostname matching is reported
    separately — so a name taken from the leaf's own SAN (falling back to its
    Common Name, and made concrete when it is a wildcard) is used. That turns the verifier's mandatory name check into a no-op
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
            return verification.DNSName(_concrete_dns_name(dns))
        ips = san.get_values_for_type(x509.IPAddress)
        if ips:
            return verification.IPAddress(ips[0])
    cn = leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn:
        try:
            return verification.DNSName(_concrete_dns_name([cn[0].value]))
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
