"""Certificate revocation checking via OCSP and CRL.

Given a certificate (and, ideally, its issuer) determine whether it has been
revoked, trying OCSP first and falling back to the CRL distribution points.
Both soft-fail like a browser when no authoritative answer is available. An
OCSP response or CRL is only believed once its signature has been verified
against the certificate's issuer. The
HTTP transport is the SSRF-guarded client in :mod:`certinspect.httpfetch`.
"""

from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtendedKeyUsageOID,
    ExtensionOID,
)

from certinspect.httpfetch import fetch
from certinspect.parser import is_ca_certificate

# Clock-skew tolerance when judging whether an OCSP response is still fresh.
_OCSP_CLOCK_SKEW = timedelta(minutes=5)


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


def _signed_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    """Return True if ``issuer`` is named as, and signed, ``cert``'s issuer."""
    try:
        cert.verify_directly_issued_by(issuer)
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


def _fetch_issuer(cert: x509.Certificate, timeout: float) -> x509.Certificate | None:
    """Download the issuer certificate via the AIA "CA Issuers" URL.

    The download is untrusted input, so a certificate is kept only if it really
    signed ``cert``. Return None when no usable issuer can be retrieved.
    """
    _, issuer_urls = _aia_urls(cert)
    for url in issuer_urls:
        try:
            candidate = x509.load_der_x509_certificate(fetch(url, timeout=timeout))
        except (OSError, ValueError):
            continue
        if _signed_by(cert, candidate):
            return candidate
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


def _verify_signature(
    public_key, signature: bytes, data: bytes, hash_algorithm
) -> bool:
    """Return True if ``signature`` over ``data`` verifies with ``public_key``."""
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, data, padding.PKCS1v15(), hash_algorithm)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, data, ec.ECDSA(hash_algorithm))
        elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            public_key.verify(signature, data)
        else:
            return False
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


def _names_responder(response: ocsp.OCSPResponse, cert: x509.Certificate) -> bool:
    """Return True if the response's ResponderID designates ``cert``."""
    if response.responder_name is not None:
        return response.responder_name == cert.subject
    key_id = x509.SubjectKeyIdentifier.from_public_key(cert.public_key()).digest
    return response.responder_key_hash == key_id


def _has_ocsp_signing(cert: x509.Certificate) -> bool:
    """Return True if the certificate carries the id-kp-OCSPSigning EKU."""
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return False
    return ExtendedKeyUsageOID.OCSP_SIGNING in eku


def _ocsp_signer(
    response: ocsp.OCSPResponse, issuer: x509.Certificate
) -> x509.Certificate | None:
    """Return the certificate authorized to sign ``response``, or None.

    That is the issuer itself or, per RFC 6960 section 4.2.2.2, a delegated
    responder certificate embedded in the response, issued directly by the
    issuer, carrying the id-kp-OCSPSigning EKU and currently valid.
    """
    if _names_responder(response, issuer):
        return issuer
    now = datetime.now(timezone.utc)
    for candidate in response.certificates:
        if (
            _names_responder(response, candidate)
            and _signed_by(candidate, issuer)
            and _has_ocsp_signing(candidate)
            and candidate.not_valid_before_utc <= now <= candidate.not_valid_after_utc
        ):
            return candidate
    return None


def _ocsp_authentication_error(
    response: ocsp.OCSPResponse,
    request: ocsp.OCSPRequest,
    issuer: x509.Certificate,
) -> str | None:
    """Return why ``response`` cannot be trusted as the answer to ``request``.

    The response must be about the requested certificate (a genuine answer for
    another certificate of the same CA could otherwise be replayed) and be
    validly signed by an authorized responder. Returns None when it is.
    """
    if (
        response.serial_number != request.serial_number
        or response.issuer_name_hash != request.issuer_name_hash
        or response.issuer_key_hash != request.issuer_key_hash
    ):
        return "OCSP response is for a different certificate"
    signer = _ocsp_signer(response, issuer)
    if signer is None:
        return "OCSP response is not signed by the issuer or an authorized responder"
    try:
        hash_algorithm = response.signature_hash_algorithm
    except UnsupportedAlgorithm:
        return "OCSP response uses an unsupported signature algorithm"
    if not _verify_signature(
        signer.public_key(),
        response.signature,
        response.tbs_response_bytes,
        hash_algorithm,
    ):
        return "OCSP response signature is invalid"
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
    request = builder.build()
    der_request = request.public_bytes(serialization.Encoding.DER)

    try:
        raw = fetch(ocsp_urls[0], data=der_request, timeout=timeout)
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
        # An unauthenticated REVOKED is ignored too, or an attacker could
        # get healthy certificates reported as revoked.
        problem = _ocsp_authentication_error(response, request, issuer)
        if problem is not None:
            return "UNAVAILABLE", problem
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


def _crl_coverage(
    crl: x509.CertificateRevocationList, cert: x509.Certificate
) -> str | None:
    """Return how much of ``cert``'s revocation status the CRL can speak for.

    ``"full"`` when a missing serial proves the certificate is not revoked;
    ``"partial"`` when the CRL can only prove revocation (a delta CRL, or one
    limited to some revocation reasons); None when it cannot cover ``cert`` at
    all: an indirect, attribute-only, CA-only (for an end-entity) or user-only
    (for a CA) CRL, or one with a critical extension we do not understand
    (RFC 5280 sections 5.2 and 6.3.3).
    """
    partial = False
    for extension in crl.extensions:
        value = extension.value
        if isinstance(value, x509.DeltaCRLIndicator):
            partial = True
        elif isinstance(value, x509.IssuingDistributionPoint):
            is_ca = is_ca_certificate(cert)
            if (
                value.indirect_crl
                or value.only_contains_attribute_certs
                or (value.only_contains_ca_certs and not is_ca)
                or (value.only_contains_user_certs and is_ca)
            ):
                return None
            if value.only_some_reasons:
                partial = True
        elif extension.critical:
            return None
    return "partial" if partial else "full"


def _check_crl(
    cert: x509.Certificate,
    issuer: x509.Certificate | None,
    timeout: float,
) -> tuple[str, str | None]:
    """Check revocation via the certificate's CRL distribution points.

    Download each CRL in turn and look up the certificate's serial number. A
    CRL is used only if it names the certificate's issuer, its signature
    verifies against ``issuer`` and its scope can cover the certificate, so
    without a known issuer no CRL is trusted. A partial CRL (delta, or limited
    to some reasons) can prove REVOKED but not GOOD. The first CRL that yields
    a verdict wins; otherwise the status is ``"UNAVAILABLE"`` (soft-fail).
    """
    urls = _crl_urls(cert)
    if not urls:
        return "UNAVAILABLE", "no CRL distribution point in extension"
    if issuer is None:
        return "UNAVAILABLE", "CRL cannot be verified without the issuer certificate"

    for url in urls:
        try:
            raw = fetch(url, timeout=timeout)
        except (OSError, ValueError):
            continue
        crl = _load_crl(raw)
        if crl is None:
            continue
        try:
            if crl.issuer != cert.issuer or not crl.is_signature_valid(
                issuer.public_key()
            ):
                continue
            coverage = _crl_coverage(crl, cert)
        except (TypeError, ValueError):
            continue
        if coverage is None:
            continue

        revoked = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
        if revoked is not None:
            when = getattr(revoked, "revocation_date_utc", None)
            detail = f"revoked at {when}" if when else "revoked"
            return "REVOKED", f"{detail} (via CRL)"
        if coverage == "partial":
            continue
        stale = _crl_stale(crl)
        if stale is not None:
            return "UNAVAILABLE", stale
        return "GOOD", "via CRL"

    return "UNAVAILABLE", "no usable CRL could be retrieved"


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
    Either way an issuer that did not sign ``cert`` is discarded, since every
    OCSP/CRL signature check is anchored on it.
    """
    if issuer is not None and not _signed_by(cert, issuer):
        issuer = None
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
