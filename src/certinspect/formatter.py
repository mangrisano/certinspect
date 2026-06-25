"""
formatter.py — Presentation of the results to the user.

MODULE GOAL
-----------
Take the dict produced by parser.analyze() and produce human-readable output
(text) or machine-readable output (JSON).

GUIDED STEPS (write them yourself):
1. format_human(info: dict) -> str
   - Print the fields in a tidy, readable way.
   - Highlight the status: VALID / EXPIRED / NOT YET VALID.
   - Show a WARNING if the days to expiry are < 30.
2. format_json(info: dict) -> str
   - Serialize with json.dumps(info, default=str, indent=2).
   - Note: dates are not serializable by default → use default=str
     or convert them to ISO 8601 in parser.analyze().

Hint: keep color/emoji logic optional and simple.
Do not put analysis logic here: this module only PRESENTS the data.
"""

import json

from certinspect.parser import certificate_status

LABEL_WIDTH = 16


def format_human(info: dict, warn_days: int = 30) -> str:
    """Return a human-readable text representation."""
    days = info["days_to_expire"]
    status = certificate_status(info, warn_days)

    def row(label: str, value: object) -> str:
        return f"{label + ':':<{LABEL_WIDTH}}{value}"

    lines = [
        row("Subject", info["subject"]),
        row("Status", status),
        "",
        row("Issuer", info["issuer"]),
        row("Valid from", info["not_valid_before"]),
        row("Valid until", info["not_valid_after"]),
        row("Days to expiry", days),
        "",
        row("Serial number", info["serial_number"]),
        row("Signature", info["signature_algorithm"]),
        row("Key size", f"{info['key_size']} bit"),
        row("Fingerprint", info["fingerprint_sha256"]),
        row("CA", info["is_ca"]),
        row("Self-Signed", info["self_signed"]),
    ]

    if info["weak"]:
        lines.append("")
        for reason in info["weak"]:
            lines.append(f"WARNING: {reason}")

    if info.get("hostname_match") is not None:
        lines.append(row("Hostname match", info["hostname_match"]))

    if 0 <= days < warn_days:
        lines.append("")
        lines.append(f"WARNING: certificate expires in {days} days")

    san = info["san"]
    lines.append("")
    if san:
        lines.append("SAN:")
        lines.extend(f"  - {name}" for name in san)
    else:
        lines.append(row("SAN", "(none)"))

    return "\n".join(lines)


def format_json(info: dict) -> str:
    """Return a JSON representation."""

    return json.dumps(info, indent=2, default=str)
