"""SSRF-guarded HTTP GET/POST for certificate- and CT-log-supplied URLs.

OCSP, CRL, CA-Issuer and Certificate Transparency URLs all come from untrusted
input, so this small client screens the target host against internal or
non-routable addresses and caps the response size. Shared by the revocation
checks and the CT-log discovery.
"""

import http.client
import ipaddress
import socket
import threading
import urllib.request
from urllib.parse import urlsplit

# Cap the size of any certificate-supplied HTTP response (OCSP/CRL/CA-Issuer)
# so a malicious certificate cannot point us at an unbounded download and
# exhaust memory. Real-world CRLs stay comfortably below this.
_MAX_HTTP_RESPONSE_BYTES = 16 * 1024 * 1024

# CRL/OCSP URLs legitimately redirect once or twice (http->https, a CDN).
_MAX_REDIRECTS = 5

# The socket timeout covers one read at a time; this bounds a whole fetch
# (redirects included) against a server that sends one byte at a time.
_FETCH_DEADLINE_SECONDS = 60.0

# Sockets opened by the fetch running in this thread, closed at its deadline.
_active = threading.local()


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


def _vetted_addresses(host: str, port: int | None) -> list[str]:
    """Resolve ``host`` and return its IP addresses, all of them allowed.

    Raises ValueError when the name does not resolve or when any address is
    internal or non-routable (see ``_is_blocked_fetch_address``).
    """
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError as err:
        raise ValueError(f"could not resolve {host}: {err}") from err
    addresses: list[str] = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if _is_blocked_fetch_address(ip):
            raise ValueError(
                f"refusing to fetch from {host}: {ip} is a non-routable or "
                "internal address"
            )
        if str(ip) not in addresses:
            addresses.append(str(ip))
    return addresses


def _guard_fetch_host(url: str) -> None:
    """Refuse to fetch a certificate-supplied URL pointing at an internal host.

    OCSP, CRL and CA-Issuer URLs come from the inspected certificate, i.e. from
    untrusted input; following them blindly would turn certinspect into an SSRF
    primitive able to reach the cloud metadata service or a port on localhost.
    This is the early check on the URL; the connection itself goes to an
    address vetted again at connect time (see ``_connect_vetted``), so a DNS
    answer that changes in between cannot redirect it. Raises ValueError when
    the target is not allowed, which the callers already treat as a soft-fail.
    """
    parts = urlsplit(url)
    if not parts.hostname:
        raise ValueError(f"URL has no host: {url}")
    _vetted_addresses(parts.hostname, parts.port)


def _check_url(url: str) -> None:
    """Raise ValueError unless ``url`` is an http(s) URL on an allowed host."""
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError(f"unsupported URL scheme: {url}")
    _guard_fetch_host(url)


class _GuardedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects only to URLs that pass the same checks as the first.

    Without this, a public host named in a certificate could answer with a
    redirect to loopback or the cloud metadata endpoint and urllib would follow
    it unchecked.
    """

    max_redirections = _MAX_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _track(sock: socket.socket) -> socket.socket:
    """Register ``sock`` with the fetch running in this thread, if any."""
    sockets = getattr(_active, "sockets", None)
    if sockets is not None:
        sockets.append(sock)
    return sock


def _connect_direct(address, timeout, source_address=None) -> socket.socket:
    """Connect like http.client does, to a proxy chosen by the environment."""
    return _track(socket.create_connection(address, timeout, source_address))


def _connect_vetted(address, timeout, source_address=None) -> socket.socket:
    """Connect to a vetted IP of ``address``'s host, never re-resolving it.

    Resolving once and connecting to that exact address closes the DNS
    rebinding window: an attacker's name server cannot answer the check with a
    public IP and the connection with loopback. TLS still verifies the
    certificate against the original host name.
    """
    host, port = address
    error: OSError | None = None
    for ip in _vetted_addresses(host, port):
        try:
            return _track(socket.create_connection((ip, port), timeout, source_address))
        except OSError as err:
            error = err
    raise error or OSError(f"could not connect to {host}")


def _connection_class(base: type, connect) -> type:
    """Return ``base`` with its socket opened by ``connect``."""

    class _Connection(base):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            # http.client's connection hook; HTTPSConnection wraps this socket.
            self._create_connection = connect

    return _Connection


_PINNED_HTTP = _connection_class(http.client.HTTPConnection, _connect_vetted)
_PINNED_HTTPS = _connection_class(http.client.HTTPSConnection, _connect_vetted)
_PROXIED_HTTP = _connection_class(http.client.HTTPConnection, _connect_direct)
_PROXIED_HTTPS = _connection_class(http.client.HTTPSConnection, _connect_direct)


def _via_proxy(req: urllib.request.Request) -> bool:
    """True when urllib routes ``req`` through a proxy from the environment.

    The proxy then resolves the target itself, so pinning cannot apply; only
    the URL check guards those requests.
    """
    return req.has_proxy() or bool(getattr(req, "_tunnel_host", None))


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_PROXIED_HTTP if _via_proxy(req) else _PINNED_HTTP, req)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(
            _PROXIED_HTTPS if _via_proxy(req) else _PINNED_HTTPS,
            req,
            context=self._context,
        )


def _build_opener(proxy: str | None = None, no_proxy: bool = False):
    handlers = [_GuardedRedirectHandler, _PinnedHTTPHandler, _PinnedHTTPSHandler]
    if no_proxy:
        handlers.append(urllib.request.ProxyHandler({}))
    elif proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    return urllib.request.build_opener(*handlers)


_OPENER = _build_opener()


def use_proxy(proxy: str | None, no_proxy: bool = False) -> None:
    """Route every later fetch through ``proxy``, or directly with ``no_proxy``.

    Mirrors --proxy/--no-proxy for the TLS connections; with neither, the
    environment proxy (``HTTPS_PROXY``/``HTTP_PROXY``, ``NO_PROXY``) applies.
    """
    global _OPENER
    _OPENER = _build_opener(proxy, no_proxy)


def fetch(url: str, *, data: bytes | None = None, timeout: float) -> bytes:
    """Perform a minimal HTTP(S) GET/POST and return the response body.

    Only ``http`` and ``https`` URLs are accepted; the URLs come from the
    certificate's own AIA/CRL extensions, i.e. from untrusted input, so the
    target host is screened against internal/non-routable addresses — on the
    first request and on every redirect — and the response size is capped. A
    POST is used when ``data`` is given. The whole fetch must finish within
    ``_FETCH_DEADLINE_SECONDS`` (TimeoutError otherwise); a malformed HTTP
    response raises ValueError.
    """
    _check_url(url)
    headers = {"Content-Type": "application/ocsp-request"} if data else {}
    request = urllib.request.Request(url, data=data, headers=headers)
    sockets: list[socket.socket] = []
    expired = threading.Event()

    def expire() -> None:
        expired.set()
        for sock in list(sockets):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    timer = threading.Timer(_FETCH_DEADLINE_SECONDS, expire)
    timer.daemon = True
    _active.sockets = sockets
    timer.start()
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            body = response.read(_MAX_HTTP_RESPONSE_BYTES + 1)
    except (OSError, http.client.HTTPException) as err:
        if expired.is_set():
            raise _deadline_error(url) from err
        if isinstance(err, http.client.HTTPException):
            raise ValueError(f"malformed HTTP response from {url}: {err!r}") from err
        raise
    finally:
        timer.cancel()
        _active.sockets = None
    if expired.is_set():
        raise _deadline_error(url)
    if len(body) > _MAX_HTTP_RESPONSE_BYTES:
        raise ValueError(
            f"response from {url} exceeds the {_MAX_HTTP_RESPONSE_BYTES}-byte limit"
        )
    return body


def _deadline_error(url: str) -> TimeoutError:
    return TimeoutError(f"fetching {url} took longer than {_FETCH_DEADLINE_SECONDS:g}s")
