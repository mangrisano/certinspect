"""Present the analysis results to the user.

Take the dict produced by parser.analyze() and render it either as
human-readable text or as JSON. This module only PRESENTS data; all the
analysis logic lives in parser.py.
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
        row("Total validity", f"{info['validity_days']} days"),
        "",
        row("Serial number", info["serial_number"]),
        row("Signature", info["signature_algorithm"]),
        row("Key size", f"{info['key_size']} bit"),
        row("Fingerprint", info["fingerprint_sha256"]),
        row("CA", info["is_ca"]),
        row("Self-Signed", info["self_signed"]),
    ]

    if info.get("tls_version"):
        lines.append(row("TLS version", info["tls_version"]))
    if info.get("cipher"):
        lines.append(row("Cipher", info["cipher"]))

    if info["key_usage"]:
        lines.append(row("Key usage", ", ".join(info["key_usage"])))
    if info["extended_key_usage"]:
        lines.append(row("Ext. key usage", ", ".join(info["extended_key_usage"])))

    if info["weak"]:
        lines.append("")
        for reason in info["weak"]:
            lines.append(f"WARNING: {reason}")

    if info.get("hostname_match") is not None:
        lines.append(row("Hostname match", info["hostname_match"]))

    if "chain_trusted" in info:
        lines.append(row("Chain trusted", info["chain_trusted"]))
        if not info["chain_trusted"] and info.get("chain_error"):
            lines.append(f"WARNING: chain not trusted ({info['chain_error']})")

    if info.get("revocation_status"):
        lines.append(row("Revocation", info["revocation_status"]))
        if info["revocation_status"] == "REVOKED" and info.get("revocation_detail"):
            lines.append(f"WARNING: certificate revoked ({info['revocation_detail']})")

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
