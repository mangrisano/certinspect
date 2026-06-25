"""X.509 certificate parsing and analysis.

Turns certificate bytes (DER or PEM) into a dictionary of fields ready to be
formatted for the user.
"""

from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa


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


def format_fingerprint(cert: x509.Certificate) -> str:
    return ":".join(f"{b:02X}" for b in cert.fingerprint(hashes.SHA256()))


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


def analyze(cert: x509.Certificate) -> dict:
    """Extract the relevant information from the certificate as a dict."""

    now = datetime.now(timezone.utc)
    days_to_expire = (cert.not_valid_after_utc - now).days
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san = []

    try:
        ext = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        is_ca = ext.value.ca
    except x509.ExtensionNotFound:
        is_ca = False

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
        "key_size": cert.public_key().key_size,
        "san": san,
        "fingerprint_sha256": format_fingerprint(cert),
        "is_ca": is_ca,
        "self_signed": cert.subject == cert.issuer,
        "weak": weak,
    }


def certificate_status(info: dict, warn_days: int = 30) -> str:
    """Return the validity status derived from the analyzed data.

    One of: 'INVALID DATES', 'EXPIRED', 'EXPIRING', 'VALID'.
    'EXPIRING' means the certificate is still valid but expires within
    ``warn_days`` days.
    """

    if info["not_valid_before"] > info["not_valid_after"]:
        return "INVALID DATES"
    days = info["days_to_expire"]
    if days < 0:
        return "EXPIRED"
    if days < warn_days:
        return "EXPIRING"
    return "VALID"
