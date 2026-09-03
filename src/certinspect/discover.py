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
from urllib.parse import urlencode

from certinspect.fetch import _http

# crt.sh search front end. The `%` in the query is a SQL LIKE wildcard matching
# any subdomain label; `output=json` asks for machine-readable results.
_CRT_SH_URL = "https://crt.sh/"


def _extract_names(records: list[dict], domain: str) -> set[str]:
    """Return the concrete hostnames under ``domain`` found in CT records.

    Each crt.sh record carries a ``common_name`` and a ``name_value`` holding
    one or more newline-separated identities. Wildcards (``*.example.com``) are
    dropped because they name no single host to connect to, and any identity
    outside ``domain`` (crt.sh occasionally returns neighbours) is ignored.
    Matching is case-insensitive.
    """
    domain = domain.lower().strip(".")
    suffix = f".{domain}"
    names: set[str] = set()
    for record in records:
        common = record.get("common_name") or ""
        listed = record.get("name_value") or ""
        for line in f"{common}\n{listed}".splitlines():
            name = line.strip().lower().rstrip(".")
            if not name or "*" in name:
                continue
            if name == domain or name.endswith(suffix):
                names.add(name)
    return names


def discover_hostnames(domain: str, timeout: float) -> list[str]:
    """Return the sorted unique hostnames CT has seen a cert for under ``domain``.

    Queries crt.sh for certificates issued to any subdomain of ``domain`` and
    returns the concrete (non-wildcard) hostnames, ready to be inspected as
    ordinary targets. Raises ValueError when the response cannot be parsed.
    """
    query = urlencode({"q": f"%.{domain}", "output": "json"})
    body = _http(f"{_CRT_SH_URL}?{query}", timeout=timeout)
    try:
        records = json.loads(body)
    except json.JSONDecodeError as err:
        raise ValueError(f"could not parse the crt.sh response: {err}") from err
    if not isinstance(records, list):
        raise ValueError("unexpected crt.sh response: expected a JSON array")
    return sorted(_extract_names(records, domain))
