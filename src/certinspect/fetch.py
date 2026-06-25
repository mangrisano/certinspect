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


def get_server_cert(
    host: str, port: int = 443, timeout: float = 5.0
) -> tuple[bytes, dict]:
    """Return the server certificate (DER bytes) and connection info.

    The connection info is a dict with the negotiated ``tls_version`` and
    ``cipher`` suite name.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
            cipher = ssock.cipher()
            conn = {
                "tls_version": ssock.version(),
                "cipher": cipher[0] if cipher else None,
            }
            return der, conn


def verify_chain(
    host: str, port: int = 443, timeout: float = 5.0
) -> tuple[bool, str | None, list[x509.Certificate]]:
    """Check whether the server's certificate chain is trusted.

    Open a fully verified TLS handshake (system trust store, hostname check)
    as a browser would. Return ``(trusted, reason, chain)`` where ``chain`` is
    the verified certificate chain (leaf first) when the interpreter exposes
    it (Python 3.13+) and verification succeeds, otherwise an empty list.
    ``reason`` is None on success or the verification message on failure.
    Network-level failures are left to propagate.
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
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


def check_revocation(
    cert: x509.Certificate,
    timeout: float = 5.0,
    issuer: x509.Certificate | None = None,
) -> tuple[str, str | None]:
    """Check the certificate's revocation status via OCSP.

    Return ``(status, detail)`` where status is one of:

    * ``"GOOD"`` — the responder confirms the certificate is valid.
    * ``"REVOKED"`` — the responder confirms the certificate is revoked.
    * ``"UNKNOWN"`` — the responder does not know this certificate.
    * ``"UNAVAILABLE"`` — no OCSP URL, issuer unavailable, or a responder
      error (soft-fail, like a browser).

    When ``issuer`` is provided (e.g. from the verified TLS chain) it is used
    directly; otherwise the issuer is downloaded via the AIA "CA Issuers" URL.
    ``detail`` carries extra context (e.g. the revocation time) when useful.
    No CRL fallback is performed.
    """
    ocsp_urls, _ = _aia_urls(cert)
    if not ocsp_urls:
        return "UNAVAILABLE", "no OCSP responder in AIA extension"

    if issuer is None:
        issuer = _fetch_issuer(cert, timeout)
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
