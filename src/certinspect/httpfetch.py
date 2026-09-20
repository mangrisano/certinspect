"""SSRF-guarded HTTP GET/POST for certificate- and CT-log-supplied URLs.

OCSP, CRL, CA-Issuer and Certificate Transparency URLs all come from untrusted
input, so this small client screens the target host against internal or
non-routable addresses and caps the response size. Shared by the revocation
checks and the CT-log discovery.
"""

import ipaddress
import socket
import urllib.request
from urllib.parse import urlsplit

# Cap the size of any certificate-supplied HTTP response (OCSP/CRL/CA-Issuer)
# so a malicious certificate cannot point us at an unbounded download and
# exhaust memory. Real-world CRLs stay comfortably below this.
_MAX_HTTP_RESPONSE_BYTES = 16 * 1024 * 1024


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
