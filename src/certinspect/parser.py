"""X.509 certificate parsing and analysis.

Turns certificate bytes (DER or PEM) into a dictionary of fields ready to be
formatted for the user.
"""

from datetime import date, datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import NameOID


class CertificateLoadError(ValueError): ...


def to_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _name_matches(pattern: str, hostname: str) -> bool:
    pattern = pattern.lower()
    hostname = hostname.lower()
    if pattern.startswith("*."):
        head, _, tail = hostname.partition(".")
        return bool(head) and tail == pattern[2:]

    return pattern == hostname


def hostname_matches(info: dict, hostname: str) -> bool:
    """Return True if hostname is covered by the certificate's SAN names."""
    return any(_name_matches(name, hostname) for name in info["san"])


def missing_san_names(info: dict, expected: list[str]) -> list[str]:
    """Return the expected names not covered by the certificate's SAN.

    Each name is matched with the same wildcard rules as ``hostname_matches``
    (a leading ``*.`` covers exactly one label). The returned list preserves
    the input order and is empty when every name is covered.
    """
    return [name for name in expected if not hostname_matches(info, name)]


def format_fingerprint(cert: x509.Certificate) -> str:
    return ":".join(f"{b:02X}" for b in cert.fingerprint(hashes.SHA256()))


def pin_matches(info: dict, pin: str) -> bool:
    """Return True if the SHA-256 fingerprint equals the expected pin.

    The comparison ignores colons and case, so both ``AA:BB:..`` and
    ``aabb..`` forms are accepted.
    """
    normalized = info["fingerprint_sha256"].replace(":", "").lower()
    return normalized == pin.replace(":", "").lower()


def chain_summary(cert: x509.Certificate) -> dict:
    """Return a compact summary of a chain certificate for display/JSON."""
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_valid_after": cert.not_valid_after_utc,
        "serial_number": cert.serial_number,
        "is_ca": _is_ca(cert),
    }


def _short_name(cert: x509.Certificate) -> str:
    """Return the certificate's Common Name, or its full subject DN."""
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return attrs[0].value if attrs else cert.subject.rfc4514_string()


def chain_expiry_warnings(
    chain: list[x509.Certificate], warn_days: int = 30
) -> list[str]:
    """Return warnings for non-leaf chain certs that are expired or near expiry.

    The leaf (index 0) is skipped — its own expiry is already reported as the
    certificate status. Each intermediate or root certificate that has already
    expired, or expires within ``warn_days`` days, yields one warning string.
    An expired intermediate silently breaks the chain, so surfacing it early is
    valuable even when ``--verify`` is not used.
    """
    now = datetime.now(timezone.utc)
    warnings: list[str] = []
    for cert in chain[1:]:
        days = (cert.not_valid_after_utc - now).days
        name = _short_name(cert)
        if days < 0:
            warnings.append(f"chain certificate '{name}' expired {-days} days ago")
        elif days < warn_days:
            warnings.append(f"chain certificate '{name}' expires in {days} days")
    return warnings


def _is_ca(cert: x509.Certificate) -> bool:
    """Return the BasicConstraints CA flag, or False if the extension is absent."""
    try:
        ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        return ext.value.ca
    except x509.ExtensionNotFound:
        return False


def _weak_key(public_key) -> str | None:
    """Return a warning if the key is below safe size for its type.

    RSA/DSA need >= 2048 bit; EC needs >= 256 bit. Other key types
    (e.g. Ed25519) are always considered strong.
    """
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        if public_key.key_size < 256:
            return f"Weak EC key ({public_key.key_size} bit)"
    elif isinstance(public_key, (rsa.RSAPublicKey, dsa.DSAPublicKey)):
        if public_key.key_size < 2048:
            return f"Weak key ({public_key.key_size} bit)"
    return None


def load_certificate(data: bytes) -> x509.Certificate:
    """Load a certificate from DER or PEM bytes."""
    if not data:
        raise CertificateLoadError("There is no certificate to load.")
    try:
        return x509.load_der_x509_certificate(data)
    except ValueError:
        return x509.load_pem_x509_certificate(data)


def _key_usage(cert: x509.Certificate) -> list[str]:
    """Return the enabled KeyUsage names, or [] if the extension is absent."""
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return []
    names = [
        "digital_signature",
        "content_commitment",
        "key_encipherment",
        "data_encipherment",
        "key_agreement",
        "key_cert_sign",
        "crl_sign",
    ]
    usages = [name for name in names if getattr(ku, name)]
    # encipher_only / decipher_only are only meaningful with key_agreement.
    if ku.key_agreement:
        if ku.encipher_only:
            usages.append("encipher_only")
        if ku.decipher_only:
            usages.append("decipher_only")
    return usages


def _extended_key_usage(cert: x509.Certificate) -> list[str]:
    """Return the ExtendedKeyUsage names, or [] if the extension is absent."""
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        return []
    return [oid._name for oid in eku]


def _sct_count(cert: x509.Certificate) -> int:
    """Return the number of Signed Certificate Timestamps embedded in the cert.

    SCTs prove the certificate was submitted to Certificate Transparency logs;
    modern browsers distrust publicly-trusted certificates that carry none.
    Only the SCTs embedded in the certificate are counted, not those a server
    may deliver via the TLS handshake or OCSP stapling. Returns 0 when the
    extension is absent.
    """
    try:
        ext = cert.extensions.get_extension_for_class(
            x509.PrecertificateSignedCertificateTimestamps
        )
    except x509.ExtensionNotFound:
        return 0
    return len(ext.value)


def _must_staple(cert: x509.Certificate) -> bool:
    """Return whether the certificate carries the OCSP Must-Staple extension.

    Must-Staple (RFC 7633: the TLS Feature extension with ``status_request``)
    tells clients to reject the connection unless the server presents a stapled
    OCSP response, closing the OCSP soft-fail hole. Returns False when the
    extension is absent.
    """
    try:
        ext = cert.extensions.get_extension_for_class(x509.TLSFeature)
    except x509.ExtensionNotFound:
        return False
    return x509.TLSFeatureType.status_request in ext.value


def analyze(cert: x509.Certificate) -> dict:
    """Extract the relevant information from the certificate as a dict."""
    now = datetime.now(timezone.utc)
    days_to_expire = (cert.not_valid_after_utc - now).days
    validity_days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_value = ext.value
        san = list(san_value.get_values_for_type(x509.DNSName))
        san += [str(ip) for ip in san_value.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        san = []

    is_ca = _is_ca(cert)

    weak = []
    reason = _weak_key(cert.public_key())
    if reason:
        weak.append(reason)
    sig = cert.signature_algorithm_oid._name.lower()
    if "sha1" in sig or "md5" in sig:
        weak.append(f"Weak signature ({cert.signature_algorithm_oid._name})")

    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_valid_before": cert.not_valid_before_utc,
        "not_valid_after": cert.not_valid_after_utc,
        "serial_number": cert.serial_number,
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "days_to_expire": days_to_expire,
        "validity_days": validity_days,
        "key_size": cert.public_key().key_size,
        "san": san,
        "fingerprint_sha256": format_fingerprint(cert),
        "is_ca": is_ca,
        "self_signed": cert.subject == cert.issuer,
        "key_usage": _key_usage(cert),
        "extended_key_usage": _extended_key_usage(cert),
        "sct_count": _sct_count(cert),
        "must_staple": _must_staple(cert),
        "weak": weak,
    }


def certificate_status(
    info: dict, warn_days: int = 30, critical_days: int | None = None
) -> str:
    """Return the validity status derived from the analyzed data.

    One of: 'INVALID DATES', 'NOT YET VALID', 'EXPIRED', 'CRITICAL',
    'EXPIRING', 'VALID'. 'NOT YET VALID' means the certificate's validity
    period starts in the future (it cannot be used yet). 'EXPIRING' means the
    certificate is still valid but expires within ``warn_days`` days; when
    ``critical_days`` is given, a certificate that expires within that tighter
    window is reported as 'CRITICAL' instead.
    """
    if info["not_valid_before"] > info["not_valid_after"]:
        return "INVALID DATES"
    if info["not_valid_before"] > datetime.now(timezone.utc):
        return "NOT YET VALID"
    days = info["days_to_expire"]
    if days < 0:
        return "EXPIRED"
    if critical_days is not None and days < critical_days:
        return "CRITICAL"
    if days < warn_days:
        return "EXPIRING"
    return "VALID"


# CA/Browser Forum TLS validity cap and its scheduled reductions (ballot
# SC-081): 398 days today, then 200, 100 and finally 47 days. Each entry is the
# date the new maximum takes effect, newest first so the first match wins.
_CAB_FORUM_SCHEDULE: tuple[tuple[date, int], ...] = (
    (date(2029, 3, 15), 47),
    (date(2027, 3, 15), 100),
    (date(2026, 3, 15), 200),
)
_CAB_FORUM_DEFAULT = 398


def cab_forum_max_validity(today: date | None = None) -> int:
    """Return the CA/Browser Forum maximum TLS validity (in days) on ``today``.

    The Baseline Requirements shorten the cap on fixed dates: 398 days until
    2026-03-15, then 200, then 100 days from 2027-03-15, and 47 days from
    2029-03-15. ``today`` defaults to the current date, so the value tracks the
    schedule automatically.
    """
    if today is None:
        today = date.today()
    for start, limit in _CAB_FORUM_SCHEDULE:
        if today >= start:
            return limit
    return _CAB_FORUM_DEFAULT


# TLS/SSL protocol versions ordered oldest -> newest, using the strings that
# ``ssl.SSLSocket.version()`` reports. The index is a comparable rank.
_TLS_VERSION_ORDER = (
    "SSLv2",
    "SSLv3",
    "TLSv1",
    "TLSv1.1",
    "TLSv1.2",
    "TLSv1.3",
)


def tls_version_rank(version: str) -> int | None:
    """Return a comparable rank for a TLS/SSL version, or None if unknown.

    Accepts the strings ssl reports ("TLSv1.3", "TLSv1", ...); "TLSv1.0" is
    treated as "TLSv1". Newer versions rank higher.
    """
    normalized = "TLSv1" if version == "TLSv1.0" else version
    order = {name: rank for rank, name in enumerate(_TLS_VERSION_ORDER)}
    return order.get(normalized)


def policy_violations(
    info: dict,
    *,
    not_after_max: int | None = None,
    min_key_size: int | None = None,
    fail_weak: bool = False,
    require_sct: bool = False,
    require_must_staple: bool = False,
    min_tls_version: str | None = None,
) -> list[str]:
    """Return the opt-in policy violations for the analyzed certificate.

    Each argument enables one check; when none is set the list is always
    empty, so the certificate's exit code is unaffected:

    * ``not_after_max`` — the total validity must not exceed this many days
      (e.g. 398 for the current CA/Browser Forum maximum).
    * ``min_key_size`` — the public key must be at least this many bits.
    * ``fail_weak`` — promote the warnings already collected in ``info["weak"]``
      (weak key size, SHA-1/MD5 signature) to hard violations.
    * ``require_sct`` — the certificate must embed at least one Signed
      Certificate Timestamp (Certificate Transparency).
    * ``require_must_staple`` — the certificate must carry the OCSP
      Must-Staple extension (RFC 7633 TLS Feature ``status_request``).
    * ``min_tls_version`` — the negotiated TLS version (``info["tls_version"]``,
      only present for host targets) must be at least this version.

    The returned strings are ready to display; the list preserves check order
    and is empty when the certificate satisfies every enabled policy.
    """
    violations: list[str] = []
    if not_after_max is not None and info["validity_days"] > not_after_max:
        violations.append(
            f"total validity {info['validity_days']} days exceeds the "
            f"{not_after_max}-day maximum"
        )
    if min_key_size is not None and info["key_size"] < min_key_size:
        violations.append(
            f"key size {info['key_size']} bit is below the {min_key_size}-bit minimum"
        )
    if fail_weak:
        violations.extend(info["weak"])
    if require_sct and not info["sct_count"]:
        violations.append(
            "no embedded Signed Certificate Timestamps (Certificate Transparency)"
        )
    if require_must_staple and not info["must_staple"]:
        violations.append("missing OCSP Must-Staple extension")
    if min_tls_version is not None:
        negotiated = info.get("tls_version")
        min_rank = tls_version_rank(min_tls_version)
        neg_rank = tls_version_rank(negotiated) if negotiated else None
        if neg_rank is not None and min_rank is not None and neg_rank < min_rank:
            violations.append(
                f"TLS version {negotiated} is below the required {min_tls_version}"
            )
    return violations
