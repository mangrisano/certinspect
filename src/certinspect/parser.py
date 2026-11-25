"""X.509 certificate parsing and analysis.

Turns certificate bytes (DER or PEM) into a dictionary of fields ready to be
formatted for the user.
"""

import hmac
import ipaddress
from collections.abc import Callable
from datetime import date, datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID
from certinspect.exit_codes import RevocationStatus, Status
from certinspect.models import CertificateInfo


class CertificateLoadError(ValueError): ...


# Human-readable names for the OIDs certinspect surfaces, keyed by each OID's
# immutable dotted string. This replaces cryptography's private, undocumented
# ObjectIdentifier._name, which drifts between versions and even returns
# "Unknown OID" for several well-known OIDs.
_SIGNATURE_ALGORITHM_NAMES = {
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.14": "sha224WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.10": "rsassaPss",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.1": "ecdsa-with-SHA224",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.2.840.10040.4.3": "dsa-with-sha1",
    "2.16.840.1.101.3.4.3.1": "dsa-with-sha224",
    "2.16.840.1.101.3.4.3.2": "dsa-with-sha256",
    "1.3.101.112": "ed25519",
    "1.3.101.113": "ed448",
}

_EXTENDED_KEY_USAGE_NAMES = {
    "1.3.6.1.5.5.7.3.1": "serverAuth",
    "1.3.6.1.5.5.7.3.2": "clientAuth",
    "1.3.6.1.5.5.7.3.3": "codeSigning",
    "1.3.6.1.5.5.7.3.4": "emailProtection",
    "1.3.6.1.5.5.7.3.8": "timeStamping",
    "1.3.6.1.5.5.7.3.9": "OCSPSigning",
    "2.5.29.37.0": "anyExtendedKeyUsage",
    "1.3.6.1.4.1.11129.2.4.4": "certificateTransparency",
    "1.3.6.1.5.5.7.3.17": "ipsecIKE",
    "1.3.6.1.5.2.3.5": "pkInitKDC",
    "1.3.6.1.4.1.311.20.2.2": "msSmartcardLogin",
}


def _oid_name(oid: x509.ObjectIdentifier, names: dict[str, str]) -> str:
    """Return the friendly name for oid, or its dotted string if unmapped."""
    return names.get(oid.dotted_string, oid.dotted_string)


def to_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Return the parsed IP address if ``value`` is an IP literal, else None."""
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _normalize_dns(name: str) -> str:
    """Normalize a DNS name: strip trailing root dot, apply IDNA, lowercase."""
    stripped = name.rstrip(".").lower()
    if stripped.isascii():
        return stripped
    try:
        if stripped.startswith("*."):
            return "*." + stripped[2:].encode("idna").decode("ascii")
        return stripped.encode("idna").decode("ascii")
    except UnicodeError:
        return stripped


def _name_matches(pattern: str, hostname: str) -> bool:
    pattern_ip = _parse_ip(pattern)
    host_ip = _parse_ip(hostname)
    if pattern_ip is not None or host_ip is not None:
        return pattern_ip is not None and pattern_ip == host_ip

    pattern = _normalize_dns(pattern)
    hostname = _normalize_dns(hostname)
    if pattern.startswith("*."):
        head, _, tail = hostname.partition(".")
        return bool(head) and tail == pattern[2:]

    return pattern == hostname


def hostname_matches(info: CertificateInfo, hostname: str) -> bool:
    """Return True if hostname is covered by the certificate's SAN names."""
    return any(_name_matches(name, hostname) for name in info["san"])


def missing_san_names(info: CertificateInfo, expected: list[str]) -> list[str]:
    """Return the expected names not covered by the certificate's SAN.

    Each name is matched with the same wildcard rules as ``hostname_matches``
    (a leading ``*.`` covers exactly one label). The returned list preserves
    the input order and is empty when every name is covered.
    """
    return [name for name in expected if not hostname_matches(info, name)]


def format_fingerprint(cert: x509.Certificate) -> str:
    return ":".join(f"{b:02X}" for b in cert.fingerprint(hashes.SHA256()))


def pin_matches(info: CertificateInfo, pin: str) -> bool:
    """Return True if the SHA-256 fingerprint equals the expected pin.

    The comparison ignores colons and case, so both ``AA:BB:..`` and
    ``aabb..`` forms are accepted.
    """
    normalized = info["fingerprint_sha256"].replace(":", "").lower()
    return hmac.compare_digest(
        normalized.encode("ascii"),
        pin.replace(":", "").lower().encode("utf-8"),
    )


def chain_summary(cert: x509.Certificate) -> dict:
    """Return a compact summary of a chain certificate for display/JSON."""
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_valid_after": cert.not_valid_after_utc,
        "serial_number": cert.serial_number,
        "is_ca": is_ca_certificate(cert),
    }


def _short_name(cert: x509.Certificate) -> str:
    """Return the certificate's Common Name, or its full subject DN."""
    return common_name(cert.subject)


def common_name(name: x509.Name) -> str:
    """Return the Common Name of an X.509 name, or its full RFC 4514 DN."""
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if attrs and isinstance(attrs[0].value, str):
        return attrs[0].value
    return name.rfc4514_string()


def aia_urls(cert: x509.Certificate) -> tuple[list[str], list[str]]:
    """Return (ocsp_urls, ca_issuer_urls) from the certificate's AIA extension.

    Both lists are empty when the Authority Information Access extension is
    absent.
    """
    try:
        aia = cert.extensions.get_extension_for_class(
            x509.AuthorityInformationAccess
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


def diagnose_chain(presented: list[x509.Certificate]) -> dict | None:
    """Explain why a certificate chain failed to verify.

    ``presented`` is the chain exactly as sent by the server (leaf first). It is
    inspected only after verification has already failed, so the returned
    ``{"code", "detail"}`` names the most likely root cause and its remedy; it is
    not an independent trust decision. Returns None when the chain is empty
    (e.g. the interpreter cannot expose it) and nothing can be said.

    Codes:
      ``EXPIRED_IN_CHAIN``  a certificate in the chain has expired
      ``CHAIN_MISMATCH``    the sent intermediates do not sign the leaf
      ``INCOMPLETE_CHAIN``  only the leaf was sent; its public issuer is missing
      ``UNTRUSTED_ROOT``    the chain is complete but its anchor is not trusted
    """
    if not presented:
        return None
    leaf, intermediates = presented[0], presented[1:]

    now = datetime.now(timezone.utc)
    for cert in presented:
        if cert.not_valid_after_utc < now:
            role = "leaf" if cert is leaf else "chain certificate"
            return {
                "code": "EXPIRED_IN_CHAIN",
                "detail": (
                    f"{role} '{_short_name(cert)}' expired on "
                    f"{cert.not_valid_after_utc:%Y-%m-%d}"
                ),
            }

    issuer_cn = common_name(leaf.issuer)
    if any(leaf.issuer == cert.subject for cert in intermediates):
        anchor = common_name(presented[-1].issuer)
        return {
            "code": "UNTRUSTED_ROOT",
            "detail": (
                f"the chain is complete but its root '{anchor}' is not in the "
                "trust store; pass --cafile with that CA if it is internal, "
                "otherwise update the trust store"
            ),
        }

    if intermediates:
        sent = ", ".join(f"'{_short_name(cert)}'" for cert in intermediates)
        return {
            "code": "CHAIN_MISMATCH",
            "detail": (
                f"the server sent intermediate(s) {sent} that do not sign the "
                f"leaf; its real issuer '{issuer_cn}' is absent from the chain"
            ),
        }

    _, issuer_urls = aia_urls(leaf)
    if issuer_urls:
        url = issuer_urls[0]
        return {
            "code": "INCOMPLETE_CHAIN",
            "detail": (
                f"the server sent only the leaf; the intermediate '{issuer_cn}' "
                f"is missing and is published at {url}"
            ),
        }
    return {
        "code": "UNTRUSTED_ROOT",
        "detail": (
            f"the server sent only the leaf, issued by '{issuer_cn}', which is "
            "not a public CA; pass --cafile with that CA"
        ),
    }


def is_ca_certificate(cert: x509.Certificate) -> bool:
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


# Key families whose size is comparable to an RSA bit length for --min-key-size.
_SIZE_CHECKED_KEY_TYPES = ("RSA", "DSA")


def _key_type(public_key) -> str:
    """Return the public key family: RSA, EC, DSA, Ed25519 or Ed448."""
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "EC"
    if isinstance(public_key, dsa.DSAPublicKey):
        return "DSA"
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448"
    return type(public_key).__name__


def load_pkcs12_certificates(
    data: bytes, password: bytes | None = None
) -> list[x509.Certificate]:
    """Load the leaf and additional certificates from a PKCS#12 (.p12/.pfx) archive."""
    attempts: list[bytes | None] = [password]
    if password is None:
        attempts.append(b"")
    last_err: Exception | None = None
    for secret in attempts:
        try:
            _, leaf, additional = pkcs12.load_key_and_certificates(data, secret)
            certs: list[x509.Certificate] = []
            if leaf is not None:
                certs.append(leaf)
            if additional:
                certs.extend(additional)
            if not certs:
                raise CertificateLoadError(
                    "The PKCS#12 archive contains no certificates."
                )
            return certs
        except CertificateLoadError:
            raise
        except (ValueError, TypeError) as exc:
            last_err = exc
    raise CertificateLoadError(
        f"The PKCS#12 archive could not be parsed (wrong passphrase or invalid format): {last_err}"
    ) from last_err


def load_certificate(data: bytes, *, password: bytes | None = None) -> x509.Certificate:
    """Load a certificate from DER, PEM, or PKCS#12 (.p12/.pfx) bytes."""
    if not data:
        raise CertificateLoadError("There is no certificate to load.")
    try:
        return x509.load_der_x509_certificate(data)
    except ValueError:
        pass
    try:
        return x509.load_pem_x509_certificate(data)
    except ValueError as pem_exc:
        try:
            return load_pkcs12_certificates(data, password=password)[0]
        except CertificateLoadError:
            if password is not None:
                raise
            raise CertificateLoadError(
                f"The certificate could not be parsed: {pem_exc}"
            ) from pem_exc


def load_certificates(
    data: bytes, *, password: bytes | None = None
) -> list[x509.Certificate]:
    """Load every certificate from a PEM bundle, single DER cert, or PKCS#12 archive.

    A ``--file`` source may hold the full chain — leaf, intermediates and root —
    concatenated in PEM form (optionally wrapped with OpenSSL ``Bag Attributes``),
    a lone DER certificate, or a PKCS#12 (``.p12``/``.pfx``) archive.
    Certificates are returned leaf first.
    """
    if not data:
        raise CertificateLoadError("There is no certificate to load.")
    try:
        return [x509.load_der_x509_certificate(data)]
    except ValueError:
        pass
    try:
        certs = x509.load_pem_x509_certificates(data)
    except ValueError as pem_exc:
        try:
            return load_pkcs12_certificates(data, password=password)
        except CertificateLoadError:
            if password is not None:
                raise
            raise CertificateLoadError(
                f"The certificate could not be parsed: {pem_exc}"
            ) from pem_exc
    if not certs:
        raise CertificateLoadError("There is no certificate to load.")
    return certs


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
    return [_oid_name(oid, _EXTENDED_KEY_USAGE_NAMES) for oid in eku]


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


def analyze(cert: x509.Certificate) -> CertificateInfo:
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

    is_ca = is_ca_certificate(cert)
    public_key = cert.public_key()

    weak = []
    reason = _weak_key(public_key)
    if reason:
        weak.append(reason)
    sig_name = _oid_name(cert.signature_algorithm_oid, _SIGNATURE_ALGORITHM_NAMES)
    if "sha1" in sig_name.lower() or "md5" in sig_name.lower():
        weak.append(f"Weak signature ({sig_name})")

    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_valid_before": cert.not_valid_before_utc,
        "not_valid_after": cert.not_valid_after_utc,
        "serial_number": cert.serial_number,
        "signature_algorithm": sig_name,
        "days_to_expire": days_to_expire,
        "validity_days": validity_days,
        "key_type": _key_type(public_key),
        # EdDSA keys have a fixed size and expose no key_size.
        "key_size": getattr(public_key, "key_size", None),
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
    info: CertificateInfo, warn_days: int = 30, critical_days: int | None = None
) -> Status:
    """Return the validity status derived from the analyzed data.

    One of: 'INVALID DATES', 'NOT YET VALID', 'EXPIRED', 'CRITICAL',
    'EXPIRING', 'VALID'. 'NOT YET VALID' means the certificate's validity
    period starts in the future (it cannot be used yet). 'EXPIRING' means the
    certificate is still valid but expires within ``warn_days`` days; when
    ``critical_days`` is given, a certificate that expires within that tighter
    window is reported as 'CRITICAL' instead.
    """
    if info["not_valid_before"] > info["not_valid_after"]:
        return Status.INVALID_DATES
    if info["not_valid_before"] > datetime.now(timezone.utc):
        return Status.NOT_YET_VALID
    days = info["days_to_expire"]
    if days < 0:
        return Status.EXPIRED
    if critical_days is not None and days < critical_days:
        return Status.CRITICAL
    if days < warn_days:
        return Status.EXPIRING
    return Status.VALID


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
_TLS_VERSION_RANK = {name: rank for rank, name in enumerate(_TLS_VERSION_ORDER)}


def tls_version_rank(version: str) -> int | None:
    """Return a comparable rank for a TLS/SSL version, or None if unknown.

    Accepts the strings ssl reports ("TLSv1.3", "TLSv1", ...); "TLSv1.0" is
    treated as "TLSv1". Newer versions rank higher.
    """
    normalized = "TLSv1" if version == "TLSv1.0" else version
    return _TLS_VERSION_RANK.get(normalized)


PolicyRule = Callable[[CertificateInfo], list[str]]


def _rule_not_after_max(limit: int) -> PolicyRule:
    def _check(info: CertificateInfo) -> list[str]:
        if info["validity_days"] > limit:
            return [
                f"total validity {info['validity_days']} days exceeds the "
                f"{limit}-day maximum"
            ]
        return []

    return _check


def _rule_min_key_size(minimum: int) -> PolicyRule:
    def _check(info: CertificateInfo) -> list[str]:
        if (
            info["key_type"] in _SIZE_CHECKED_KEY_TYPES
            and info["key_size"] is not None
            and info["key_size"] < minimum
        ):
            return [
                f"key size {info['key_size']} bit is below the {minimum}-bit minimum"
            ]
        return []

    return _check


def _rule_fail_weak(info: CertificateInfo) -> list[str]:
    return list(info["weak"])


def _rule_require_sct(info: CertificateInfo) -> list[str]:
    if not info["sct_count"]:
        return ["no embedded Signed Certificate Timestamps (Certificate Transparency)"]
    return []


def _rule_require_must_staple(info: CertificateInfo) -> list[str]:
    if not info["must_staple"]:
        return ["missing OCSP Must-Staple extension"]
    return []


def _rule_min_tls_version(min_tls_version: str) -> PolicyRule:
    min_rank = tls_version_rank(min_tls_version)

    def _check(info: CertificateInfo) -> list[str]:
        negotiated = info.get("tls_version")
        neg_rank = tls_version_rank(negotiated) if negotiated else None
        if neg_rank is not None and min_rank is not None and neg_rank < min_rank:
            return [f"TLS version {negotiated} is below the required {min_tls_version}"]
        return []

    return _check


def _rule_require_revocation_check(info: CertificateInfo) -> list[str]:
    status = info.get("revocation_status")
    if status == RevocationStatus.GOOD:
        return []
    detail = info.get("revocation_detail")
    if detail:
        return [f"revocation check did not return GOOD ({status}: {detail})"]
    return [f"revocation check did not return GOOD ({status or 'not run'})"]


def _rule_legacy_tls(info: CertificateInfo) -> list[str]:
    accepted = info.get("legacy_tls_accepted") or []
    if accepted:
        return [f"server accepts deprecated TLS version(s): {', '.join(accepted)}"]
    return []


def build_policy_rules(
    *,
    not_after_max: int | None = None,
    min_key_size: int | None = None,
    fail_weak: bool = False,
    require_sct: bool = False,
    require_must_staple: bool = False,
    min_tls_version: str | None = None,
    require_revocation_check: bool = False,
    check_legacy_tls: bool = False,
) -> list[PolicyRule]:
    """Assemble the ordered list of enabled policy specifications."""
    rules: list[PolicyRule] = []
    if not_after_max is not None:
        rules.append(_rule_not_after_max(not_after_max))
    if min_key_size is not None:
        rules.append(_rule_min_key_size(min_key_size))
    if fail_weak:
        rules.append(_rule_fail_weak)
    if require_sct:
        rules.append(_rule_require_sct)
    if require_must_staple:
        rules.append(_rule_require_must_staple)
    if min_tls_version is not None:
        rules.append(_rule_min_tls_version(min_tls_version))
    if require_revocation_check:
        rules.append(_rule_require_revocation_check)
    if check_legacy_tls:
        rules.append(_rule_legacy_tls)
    return rules


def policy_violations(
    info: CertificateInfo,
    *,
    not_after_max: int | None = None,
    min_key_size: int | None = None,
    fail_weak: bool = False,
    require_sct: bool = False,
    require_must_staple: bool = False,
    min_tls_version: str | None = None,
    require_revocation_check: bool = False,
    check_legacy_tls: bool = False,
) -> list[str]:
    """Return the opt-in policy violations for the analyzed certificate.

    Each argument enables one check; when none is set the list is always
    empty, so the certificate's exit code is unaffected:

    * ``not_after_max`` — the total validity must not exceed this many days
      (e.g. 398 for the current CA/Browser Forum maximum).
    * ``min_key_size`` — an RSA or DSA public key must be at least this many
      bits. EC and EdDSA keys are not compared (their bit lengths are not on
      the RSA scale); ``fail_weak`` still catches an EC key below 256 bit.
    * ``fail_weak`` — promote the warnings already collected in ``info["weak"]``
      (weak key size, SHA-1/MD5 signature) to hard violations.
    * ``require_sct`` — the certificate must embed at least one Signed
      Certificate Timestamp (Certificate Transparency).
    * ``require_must_staple`` — the certificate must carry the OCSP
      Must-Staple extension (RFC 7633 TLS Feature ``status_request``).
    * ``min_tls_version`` — the negotiated TLS version (``info["tls_version"]``,
      only present for host targets) must be at least this version.
    * ``require_revocation_check`` — OCSP or CRL must return a definitive GOOD
      verdict.

    The returned strings are ready to display; the list preserves check order
    and is empty when the certificate satisfies every enabled policy.
    """
    rules = build_policy_rules(
        not_after_max=not_after_max,
        min_key_size=min_key_size,
        fail_weak=fail_weak,
        require_sct=require_sct,
        require_must_staple=require_must_staple,
        min_tls_version=min_tls_version,
        require_revocation_check=require_revocation_check,
        check_legacy_tls=check_legacy_tls,
    )
    violations: list[str] = []
    for rule in rules:
        violations.extend(rule(info))
    return violations


# Named policy profiles: opinionated bundles of the opt-in policy checks a
# sysadmin can enable in one go with --profile. Each maps a profile name to the
# policy knobs it turns on; an explicit flag on the command line always
# overrides the value a profile would set.
#
# The names are a plain intensity ladder (lenient < standard < strict), NOT the
# name of any official standard, and each stricter tier is a superset of the
# one below it. These are pragmatic, hand-picked presets meant to make common
# hardening levels one flag away — passing a profile is NOT a compliance
# attestation. The choices are informed by widely used guidance (the CA/Browser
# Forum Baseline Requirements for the validity cap, Certificate Transparency
# for the SCT requirement, and the common "no early TLS / strong crypto"
# baseline echoed by PCI DSS and the Mozilla server-side TLS guidelines), but
# the exact mapping below is this project's own decision. certinspect only sees
# the certificate and the handshake, so a profile can never cover the parts of
# those standards that concern server configuration or the wider environment.
#
# What each profile enables (see the individual flags for details):
#   lenient  -> --min-tls-version TLSv1.2, --fail-weak
#   standard -> lenient + --min-key-size 2048
#   strict   -> --min-tls-version TLSv1.3, --min-key-size 2048, --fail-weak,
#               --require-sct, --cab-forum
POLICY_PROFILES: dict[str, dict] = {
    # Gentle modern minimum: reject legacy TLS and weak crypto, nothing more.
    "lenient": {
        "min_tls_version": "TLSv1.2",
        "fail_weak": True,
    },
    # Recommended middle ground: adds a 2048-bit key floor to the minimum.
    "standard": {
        "min_tls_version": "TLSv1.2",
        "min_key_size": 2048,
        "fail_weak": True,
    },
    # Tightest posture: TLS 1.3, strong crypto, Certificate Transparency and
    # the CA/Browser Forum validity cap.
    "strict": {
        "min_tls_version": "TLSv1.3",
        "min_key_size": 2048,
        "fail_weak": True,
        "require_sct": True,
        "cab_forum": True,
    },
}
