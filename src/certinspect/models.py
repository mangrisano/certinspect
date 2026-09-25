"""Typed shapes shared across modules.

``analyze`` returns a plain dict that later stages enrich with the results of
each check. ``CertificateInfo`` documents that shape in one place and lets a
type checker catch key typos, without changing the runtime value: the keys are
added incrementally, so it is ``total=False`` (every key optional). Whether an
optional check ran is still signalled by the presence of its key.
``InspectionResult`` is one inspected target as handed to the renderers.
``ConnectionInfo`` is what the TLS handshake negotiated.
"""

from datetime import datetime
from typing import NamedTuple, TypedDict

from cryptography import x509

from certinspect.exit_codes import RevocationStatus, Status


class CertificateInfo(TypedDict, total=False):
    """The dictionary produced by ``analyze`` and enriched during inspection."""

    # Always set by analyze().
    subject: str
    issuer: str
    not_valid_before: datetime
    not_valid_after: datetime
    serial_number: int
    signature_algorithm: str
    days_to_expire: int
    validity_days: int
    key_type: str
    key_size: int | None
    san: list[str]
    fingerprint_sha256: str
    is_ca: bool
    self_signed: bool
    key_usage: list[str]
    extended_key_usage: list[str]
    sct_count: int
    must_staple: bool
    weak: list[str]

    # Added during inspection, each only when the relevant check runs.
    status: Status
    tls_version: str | None
    cipher: str | None
    hostname_match: bool | None
    chain_trusted: bool
    chain_error: str | None
    chain_diagnosis: dict[str, str]
    chain_warnings: list[str]
    chain: list[dict]
    revocation_status: RevocationStatus
    revocation_detail: str | None
    pin_match: bool
    expected_san_missing: list[str]
    policy_violations: list[str]


class InspectionResult(NamedTuple):
    """One inspected target: its display label, analysis and exit code.

    ``label`` is None for a lone --file, which is reported unlabelled. Being a
    tuple, it still unpacks as ``label, info, code``.
    """

    label: str | None
    info: CertificateInfo
    code: int


class ConnectionInfo(TypedDict):
    """The handshake of ``fetch.get_server_cert``.

    ``chain`` is the chain as the server sent it, leaf first; it is empty
    before Python 3.13, which cannot expose it.
    """

    tls_version: str | None
    cipher: str | None
    chain: list[x509.Certificate]
