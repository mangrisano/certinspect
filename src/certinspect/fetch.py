"""Retrieve the certificate from a TLS server.

Connect to a host:port over TLS and obtain the server certificate in DER
format (bytes) together with basic connection info (negotiated TLS version
and cipher).

Hostname checking and verification are disabled on purpose: this tool must
be able to inspect expired or self-signed certificates without the
connection failing. Validity is computed later in parser.py.
"""

import base64
import os
import socket
import ssl
import threading
import time
import urllib.request
import warnings
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import unquote, urlsplit

from cryptography import x509
from cryptography.x509 import verification
from cryptography.x509.oid import NameOID

from certinspect.models import ConnectionInfo


def _read_connect_response(sock: socket.socket, timeout: float) -> bytes:
    """Read an HTTP CONNECT response up to the end of its header block.

    Reads one byte at a time so we never consume bytes sent immediately after
    the tunnel opens (such as a server-first STARTTLS banner). The whole
    response must arrive within ``timeout`` seconds.
    """
    reader = _Deadline(sock, timeout)
    buf = bytearray()
    while not buf.endswith(b"\r\n\r\n"):
        if len(buf) >= 65536:
            break
        chunk = reader.recv(1)
        if not chunk:
            break
        buf += chunk
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


def resolve_host_ips(
    host: str, port: int = 443, family: int = socket.AF_UNSPEC
) -> list[str]:
    """Resolve ``host`` and return deduplicated IP addresses in DNS order.

    ``family`` filters the address family (``AF_INET``, ``AF_INET6``, or
    ``AF_UNSPEC`` for both). Raises ``OSError`` when resolution fails.
    """
    infos = socket.getaddrinfo(host, port, family=family, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(str(info[4][0]) for info in infos))


def _open_socket(
    host: str,
    port: int,
    connect_timeout: float,
    read_timeout: float,
    proxy: str | None = None,
    family: int = socket.AF_UNSPEC,
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
        if family == socket.AF_UNSPEC:
            sock = socket.create_connection((host, port), timeout=connect_timeout)
        else:
            last_err: OSError | None = None
            opened: socket.socket | None = None
            for ip in resolve_host_ips(host, port, family=family):
                try:
                    opened = socket.create_connection(
                        (ip, port), timeout=connect_timeout
                    )
                    break
                except OSError as err:
                    last_err = err
            if opened is None:
                raise last_err or OSError(f"could not connect to {host}")
            sock = opened
        sock.settimeout(read_timeout)
        return sock

    parts = urlsplit(proxy if "://" in proxy else f"//{proxy}")
    if not parts.hostname:
        raise ValueError("invalid proxy URL: missing host")
    if not host or any(ord(c) <= 0x20 or ord(c) == 0x7F for c in host):
        raise ValueError(f"invalid target host for proxy CONNECT: {host!r}")
    authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    sock = socket.create_connection(
        (parts.hostname, parts.port or 8080), timeout=connect_timeout
    )
    try:
        request = f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"
        if parts.username is not None:
            username = unquote(parts.username)
            password = unquote(parts.password or "")
            creds = f"{username}:{password}".encode()
            token = base64.b64encode(creds).decode("ascii")
            request += f"Proxy-Authorization: Basic {token}\r\n"
        request += "\r\n"
        sock.sendall(request.encode("ascii"))
        status_line = _read_connect_response(sock, connect_timeout).split(b"\r\n", 1)[0]
        fields = status_line.split(None, 2)
        if len(fields) < 2 or fields[1] != b"200":
            raise ValueError(
                f"proxy CONNECT to {authority} failed: "
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
    if retries < 0:
        raise ValueError("retries must be non-negative")
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


class _Deadline:
    """A read-only view of a socket that bounds the total time of its reads.

    A socket timeout applies to each ``recv`` alone, so a server sending one
    byte just before it expires could keep a read loop going indefinitely.
    """

    def __init__(self, sock: socket.socket, timeout: float):
        self._sock = sock
        self._timeout = timeout
        self._end = time.monotonic() + timeout

    def recv(self, n: int) -> bytes:
        remaining = self._end - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(
                f"server reply took longer than {self._timeout:g}s to arrive"
            )
        self._sock.settimeout(remaining)
        return self._sock.recv(n)


class _Readable(Protocol):
    def recv(self, n: int) -> bytes: ...


def _readline(sock: _Readable) -> bytes:
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


def _read_reply(sock: _Readable) -> bytes:
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


def _negotiate_starttls(
    sock: socket.socket, protocol: str, timeout: float | None = None
) -> None:
    """Run the plaintext STARTTLS handshake for ``protocol`` on ``sock``.

    Supports the line-based protocols smtp, imap, pop3 and ftp. On return the
    socket is ready to be wrapped in TLS. Raises ValueError if the server does
    not agree to upgrade. With ``timeout``, each server reply must arrive in
    full within that many seconds (TimeoutError otherwise), and the socket is
    left with that timeout for the TLS handshake.
    """
    try:
        _run_starttls(sock, protocol, timeout)
    finally:
        if timeout is not None:
            sock.settimeout(timeout)


def _starttls_smtp(sock: socket.socket, reply: Callable[[], _Readable]) -> None:
    _expect(_read_reply(reply()), b"220")
    sock.sendall(b"EHLO certinspect\r\n")
    _expect(_read_reply(reply()), b"250")
    sock.sendall(b"STARTTLS\r\n")
    _expect(_read_reply(reply()), b"220")


def _starttls_ftp(sock: socket.socket, reply: Callable[[], _Readable]) -> None:
    _expect(_read_reply(reply()), b"220")
    sock.sendall(b"AUTH TLS\r\n")
    _expect(_read_reply(reply()), b"234")


def _starttls_pop3(sock: socket.socket, reply: Callable[[], _Readable]) -> None:
    _expect(_readline(reply()), b"+OK")
    sock.sendall(b"STLS\r\n")
    _expect(_readline(reply()), b"+OK")


def _starttls_imap(sock: socket.socket, reply: Callable[[], _Readable]) -> None:
    _expect(_readline(reply()), b"* OK")
    sock.sendall(b"a001 STARTTLS\r\n")
    response = reply()
    for _ in range(_MAX_STARTTLS_REPLY_LINES):
        line = _readline(response)
        if not line:
            raise ValueError("connection closed during STARTTLS")
        if line.startswith(b"a001 "):
            _expect(line, b"a001 OK")
            return
    raise ValueError("STARTTLS reply has too many lines")


@dataclass(frozen=True)
class _StartTlsProtocol:
    default_port: int
    negotiate: Callable[[socket.socket, Callable[[], _Readable]], None]


_STARTTLS_PROTOCOLS: dict[str, _StartTlsProtocol] = {
    "smtp": _StartTlsProtocol(587, _starttls_smtp),
    "imap": _StartTlsProtocol(143, _starttls_imap),
    "pop3": _StartTlsProtocol(110, _starttls_pop3),
    "ftp": _StartTlsProtocol(21, _starttls_ftp),
}

# Standard plaintext ports for the STARTTLS-capable protocols, used as the
# default port when --port is left unset.
STARTTLS_PORTS = {
    name: proto.default_port for name, proto in _STARTTLS_PROTOCOLS.items()
}


def _run_starttls(sock: socket.socket, protocol: str, timeout: float | None) -> None:
    def reply() -> _Readable:
        return sock if timeout is None else _Deadline(sock, timeout)

    spec = _STARTTLS_PROTOCOLS.get(protocol.lower())
    if spec is None:
        raise ValueError(f"unsupported STARTTLS protocol: {protocol}")
    spec.negotiate(sock, reply)


def _connection_info(ssock: ssl.SSLSocket) -> ConnectionInfo:
    cipher = ssock.cipher()
    return ConnectionInfo(
        tls_version=ssock.version(),
        cipher=cipher[0] if cipher else None,
        chain=_chain(ssock, "get_unverified_chain"),
    )


def _handshake(
    host: str,
    port: int,
    timeout: float | tuple[float, float],
    context: ssl.SSLContext,
    *,
    starttls: str | None = None,
    servername: str | None = None,
    client_cert: str | None = None,
    client_key: str | None = None,
    proxy: str | None = None,
    no_proxy: bool = False,
    family: int = socket.AF_UNSPEC,
    include_verified_chain: bool = False,
) -> tuple[bytes, ConnectionInfo, list[x509.Certificate]]:
    if client_cert:
        context.load_cert_chain(certfile=client_cert, keyfile=client_key)
    connect_timeout, read_timeout = _split_timeout(timeout)
    resolved_proxy = _resolve_proxy(host, proxy, no_proxy)
    with _open_socket(
        host, port, connect_timeout, read_timeout, resolved_proxy, family=family
    ) as sock:
        if starttls:
            _negotiate_starttls(sock, starttls, read_timeout)
        with context.wrap_socket(sock, server_hostname=servername or host) as ssock:
            der = _peer_der(ssock)
            conn = _connection_info(ssock)
            verified = (
                _chain(ssock, "get_verified_chain") if include_verified_chain else []
            )
            return der, conn, verified


def get_server_cert(
    host: str,
    port: int = 443,
    timeout: float | tuple[float, float] = 5.0,
    starttls: str | None = None,
    servername: str | None = None,
    client_cert: str | None = None,
    client_key: str | None = None,
    proxy: str | None = None,
    no_proxy: bool = False,
    family: int = socket.AF_UNSPEC,
) -> tuple[bytes, ConnectionInfo]:
    """Return the server certificate (DER bytes) and connection info.

    The connection info holds the negotiated ``tls_version``, the ``cipher``
    suite name, and the ``chain`` presented by the server (leaf first) when
    the interpreter exposes it (Python 3.13+), otherwise [].

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
    der, conn, _ = _handshake(
        host,
        port,
        timeout,
        context,
        starttls=starttls,
        servername=servername,
        client_cert=client_cert,
        client_key=client_key,
        proxy=proxy,
        no_proxy=no_proxy,
        family=family,
    )
    return der, conn


def fetch_verified_cert(
    host: str,
    port: int = 443,
    timeout: float | tuple[float, float] = 5.0,
    starttls: str | None = None,
    cafile: str | None = None,
    capath: str | None = None,
    servername: str | None = None,
    client_cert: str | None = None,
    client_key: str | None = None,
    proxy: str | None = None,
    no_proxy: bool = False,
    family: int = socket.AF_UNSPEC,
) -> tuple[bytes, ConnectionInfo, bool, str | None, list[x509.Certificate]]:
    """Fetch and verify the server certificate in a single TLS handshake.

    When the chain is trusted, this completes in one round-trip and returns
    ``(der, conn, True, None, verified_chain)`` where ``conn["chain"]`` holds
    the chain presented by the server and ``verified_chain`` holds OpenSSL's
    verified chain. Only when chain verification fails
    (``SSLCertVerificationError``) does it fall back to an unverified handshake
    so expired or self-signed certificates can still be inspected, returning
    ``(der, conn, False, reason, [])``.
    """
    context = _trust_context(cafile, capath)
    context.check_hostname = False
    try:
        der, conn, verified = _handshake(
            host,
            port,
            timeout,
            context,
            starttls=starttls,
            servername=servername,
            client_cert=client_cert,
            client_key=client_key,
            proxy=proxy,
            no_proxy=no_proxy,
            family=family,
            include_verified_chain=True,
        )
        verified = verified or [x509.load_der_x509_certificate(der)]
        return der, conn, True, None, verified
    except ssl.SSLCertVerificationError as err:
        reason = err.verify_message or str(err)
        der, conn = get_server_cert(
            host,
            port,
            timeout,
            starttls=starttls,
            servername=servername,
            client_cert=client_cert,
            client_key=client_key,
            proxy=proxy,
            no_proxy=no_proxy,
            family=family,
        )
        return der, conn, False, reason, []


_LEGACY_TLS_VERSIONS: tuple[tuple[str, ssl.TLSVersion], ...] = (
    ("TLSv1", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
)


def probe_legacy_tls(
    host: str,
    port: int = 443,
    timeout: float | tuple[float, float] = 5.0,
    starttls: str | None = None,
    servername: str | None = None,
    client_cert: str | None = None,
    client_key: str | None = None,
    proxy: str | None = None,
    no_proxy: bool = False,
    family: int = socket.AF_UNSPEC,
) -> list[str]:
    """Return the deprecated TLS versions (TLSv1, TLSv1.1) accepted by ``host``.

    Each legacy version is probed with an explicit min/max version pin. A
    server rejection or local OpenSSL restriction counts as not accepted.
    """
    accepted: list[str] = []
    for label, version in _LEGACY_TLS_VERSIONS:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.set_ciphers("DEFAULT:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        try:
            with _WARNINGS_LOCK, warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                context.minimum_version = version
                context.maximum_version = version
        except ValueError:
            continue
        try:
            _handshake(
                host,
                port,
                timeout,
                context,
                starttls=starttls,
                servername=servername,
                client_cert=client_cert,
                client_key=client_key,
                proxy=proxy,
                no_proxy=no_proxy,
                family=family,
            )
        except (OSError, ssl.SSLError, ValueError):
            continue
        accepted.append(label)
    return accepted


def _peer_der(ssock: ssl.SSLSocket) -> bytes:
    """Return the server certificate (DER) of a completed handshake."""
    der = ssock.getpeercert(binary_form=True)
    if der is None:
        raise ValueError("the server presented no certificate")
    return der


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
    timeout: float | tuple[float, float] = 5.0,
    starttls: str | None = None,
    cafile: str | None = None,
    capath: str | None = None,
    servername: str | None = None,
    client_cert: str | None = None,
    client_key: str | None = None,
    proxy: str | None = None,
    no_proxy: bool = False,
    family: int = socket.AF_UNSPEC,
) -> tuple[bool, str | None, list[x509.Certificate]]:
    """Check whether the server's certificate chain is trusted.

    Open a TLS handshake verified against the trust store (hostname matching is
    reported separately as ``hostname_match``). Return ``(trusted, reason, chain)``
    where ``chain`` is the verified certificate chain (leaf first) on success —
    just the leaf on interpreters without ``get_verified_chain`` (before 3.13) —
    and an empty list on failure.
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
    try:
        der, _, verified = _handshake(
            host,
            port,
            timeout,
            context,
            starttls=starttls,
            servername=servername,
            client_cert=client_cert,
            client_key=client_key,
            proxy=proxy,
            no_proxy=no_proxy,
            family=family,
            include_verified_chain=True,
        )
        chain = verified or [x509.load_der_x509_certificate(der)]
        return True, None, chain
    except ssl.SSLCertVerificationError as err:
        return False, err.verify_message or str(err), []


_WARNINGS_LOCK = threading.Lock()
_TRUST_ANCHORS_LOCK = threading.Lock()
_TRUST_ANCHORS_CACHE: dict[
    tuple[str | None, str | None, int | None, int | None], list[x509.Certificate]
] = {}


def _path_mtime_ns(path: str | None) -> int | None:
    if not path:
        return None
    try:
        return os.stat(path).st_mtime_ns
    except OSError:
        return None


def trust_anchors(cafile: str | None, capath: str | None) -> list[x509.Certificate]:
    """Return the trusted root certificates for offline verification.

    Mirror the trust decision of the live ``verify_chain``: use ``cafile`` /
    ``capath`` when given (an internal/private PKI), otherwise the system trust
    store. A root the current OpenSSL/cryptography cannot parse (e.g. a legacy
    certificate with a non-positive serial) is skipped rather than aborting.
    Parsed anchors are cached per ``(cafile, capath, mtime)`` so batch offline
    verification does not re-parse the trust store on every file.
    """
    cache_key = (cafile, capath, _path_mtime_ns(cafile), _path_mtime_ns(capath))
    with _TRUST_ANCHORS_LOCK:
        cached = _TRUST_ANCHORS_CACHE.get(cache_key)
    if cached is not None:
        return list(cached)

    context = _trust_context(cafile, capath)
    anchors: list[x509.Certificate] = []
    with _WARNINGS_LOCK, warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for der in context.get_ca_certs(binary_form=True):
            try:
                anchors.append(x509.load_der_x509_certificate(der))
            except ValueError:
                continue
    with _TRUST_ANCHORS_LOCK:
        _TRUST_ANCHORS_CACHE[cache_key] = anchors
    return list(anchors)


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
    if cn and isinstance(cn[0].value, str):
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
    anchors = trust_anchors(cafile, capath)
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
