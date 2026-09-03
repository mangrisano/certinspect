"""Discover certificates for a domain from Certificate Transparency logs.

certinspect normally inspects the targets you name. Discovery turns a single
domain into the set of hostnames that Certificate Transparency has ever seen a
certificate issued for, so forgotten or shadow certificates surface on their
own. The names are then handed to the normal inspection pipeline.

The data comes from crt.sh, a public CT-log search front end, over a plain
read-only HTTPS query — no API key, no account. Only public data is read;
nothing is submitted.
"""

import json
from dataclasses import dataclass
from urllib.parse import urlencode

from certinspect.fetch import _http

# crt.sh search front end. The `%` in the query is a SQL LIKE wildcard matching
# any subdomain label; `output=json` asks for machine-readable results.
_CRT_SH_URL = "https://crt.sh/"


@dataclass(frozen=True)
class DiscoveredCert:
    """A certificate Certificate Transparency has logged for a domain.

    Carries just enough to list the CT inventory without a live handshake: the
    concrete (and wildcard) hostnames it covers under the queried domain, the
    issuer, and its validity window as the ISO strings crt.sh returns.
    """

    hostnames: tuple[str, ...]
    issuer: str
    not_before: str
    not_after: str


def _extract_names(
    records: list[dict], domain: str, *, keep_wildcards: bool = False
) -> set[str]:
    """Return the hostnames under ``domain`` found in CT records.

    Each crt.sh record carries a ``common_name`` and a ``name_value`` holding
    one or more newline-separated identities. Any identity outside ``domain``
    (crt.sh occasionally returns neighbours) is ignored, and matching is
    case-insensitive. Wildcards (``*.example.com``) are dropped by default —
    they name no single host to connect to — but kept when ``keep_wildcards``
    is set, which the CT inventory listing wants.
    """
    domain = domain.lower().strip(".")
    suffix = f".{domain}"
    names: set[str] = set()
    for record in records:
        common = record.get("common_name") or ""
        listed = record.get("name_value") or ""
        for line in f"{common}\n{listed}".splitlines():
            name = line.strip().lower().rstrip(".")
            if not name or ("*" in name and not keep_wildcards):
                continue
            if name == domain or name.endswith(suffix):
                names.add(name)
    return names


def _fetch_records(domain: str, timeout: float) -> list[dict]:
    """Query crt.sh for ``domain`` and return the parsed JSON records.

    Raises ValueError when the response is not the expected JSON array.
    """
    query = urlencode({"q": f"%.{domain}", "output": "json"})
    body = _http(f"{_CRT_SH_URL}?{query}", timeout=timeout)
    try:
        records = json.loads(body)
    except json.JSONDecodeError as err:
        raise ValueError(f"could not parse the crt.sh response: {err}") from err
    if not isinstance(records, list):
        raise ValueError("unexpected crt.sh response: expected a JSON array")
    return records


def discover_hostnames(domain: str, timeout: float) -> list[str]:
    """Return the sorted unique hostnames CT has seen a cert for under ``domain``.

    Queries crt.sh for certificates issued to any subdomain of ``domain`` and
    returns the concrete (non-wildcard) hostnames, ready to be inspected as
    ordinary targets. Raises ValueError when the response cannot be parsed.
    """
    return sorted(_extract_names(_fetch_records(domain, timeout), domain))


def discover_certificates(domain: str, timeout: float) -> list[DiscoveredCert]:
    """Return the certificates CT has logged for ``domain``, soonest expiry first.

    Unlike :func:`discover_hostnames` this keeps one entry per certificate
    (deduplicated by issuer and serial number) with its issuer and validity
    window, and keeps wildcard names, so the CT inventory can be listed without
    connecting to any host. Certificates whose names all fall outside ``domain``
    are dropped. Raises ValueError when the response cannot be parsed.
    """
    seen: dict[str, DiscoveredCert] = {}
    for record in _fetch_records(domain, timeout):
        names = _extract_names([record], domain, keep_wildcards=True)
        if not names:
            continue
        issuer = (record.get("issuer_name") or "").strip()
        serial = str(record.get("serial_number") or "")
        key = f"{issuer}\n{serial}" if serial else "\n".join(sorted(names))
        seen[key] = DiscoveredCert(
            hostnames=tuple(sorted(names)),
            issuer=issuer,
            not_before=str(record.get("not_before") or ""),
            not_after=str(record.get("not_after") or ""),
        )
    return sorted(seen.values(), key=lambda cert: cert.not_after)
