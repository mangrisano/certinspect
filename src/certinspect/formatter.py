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

    if "pin_match" in info:
        lines.append(row("Pin match", info["pin_match"]))
        if not info["pin_match"]:
            lines.append("WARNING: fingerprint does not match the expected pin")

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

    if info.get("chain"):
        lines.append("")
        lines.append("Certificate chain:")
        for i, link in enumerate(info["chain"]):
            lines.append(f"  [{i}] {link['subject']}")
            lines.append(f"      issuer:  {link['issuer']}")
            lines.append(f"      expires: {link['not_valid_after']}")
            lines.append(f"      CA:      {link['is_ca']}")

    return "\n".join(lines)


def format_json(info: dict) -> str:
    """Return a JSON representation."""
    return json.dumps(info, indent=2, default=str)


# Nagios/Icinga plugin exit codes.
NAGIOS_OK = 0
NAGIOS_WARNING = 1
NAGIOS_CRITICAL = 2
NAGIOS_UNKNOWN = 3

_NAGIOS_LABELS = {
    NAGIOS_OK: "OK",
    NAGIOS_WARNING: "WARNING",
    NAGIOS_CRITICAL: "CRITICAL",
    NAGIOS_UNKNOWN: "UNKNOWN",
}


def _nagios_severity(code: int) -> int:
    """Map a certinspect exit code to a Nagios plugin severity.

    0 (VALID) maps to OK, 3 (EXPIRING) to WARNING; every other problem
    (expired, hostname mismatch, untrusted chain, revoked, pin mismatch)
    maps to CRITICAL.
    """
    if code == 0:
        return NAGIOS_OK
    if code == 3:
        return NAGIOS_WARNING
    return NAGIOS_CRITICAL


def format_nagios(
    results: list[tuple[str | None, dict, int]],
    errors: list[tuple[str | None, str]] = (),
    warn_days: int = 30,
) -> tuple[str, int]:
    """Render results as Nagios/Icinga plugin output.

    Emits one line per target and returns ``(text, exit_code)`` where the
    exit code is the worst severity across all targets. Targets that could
    not be inspected (``errors``) are reported as CRITICAL.
    """
    lines = []
    worst = NAGIOS_OK

    for target, info, code in results:
        severity = _nagios_severity(code)
        worst = max(worst, severity)
        name = target or info["subject"]
        status = certificate_status(info, warn_days)
        days = info["days_to_expire"]
        perfdata = f"days={days};{warn_days};0"
        lines.append(
            f"{_NAGIOS_LABELS[severity]}: {name} certificate {status} "
            f"({days} days to expiry) | {perfdata}"
        )

    for target, message in errors:
        worst = max(worst, NAGIOS_CRITICAL)
        name = target or "target"
        lines.append(
            f"{_NAGIOS_LABELS[NAGIOS_CRITICAL]}: {name} unreachable ({message})"
        )

    if not lines:
        return f"{_NAGIOS_LABELS[NAGIOS_UNKNOWN]}: no targets inspected", NAGIOS_UNKNOWN
    return "\n".join(lines), worst


def _prometheus_label(value: str) -> str:
    """Escape a string for use as a Prometheus label value."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def format_prometheus(
    results: list[tuple[str | None, dict, int]],
    errors: list[tuple[str | None, str]] = (),
    warn_days: int = 30,
) -> str:
    """Render results as Prometheus textfile-collector metrics.

    Exposes one ``certinspect_up`` series per target (1 when inspected, 0
    when unreachable) plus ``certinspect_cert_expiry_days`` and
    ``certinspect_cert_valid`` for the targets that could be inspected.
    """
    up, expiry, valid = [], [], []

    for target, info, _ in results:
        label = _prometheus_label(target or info["subject"])
        days = info["days_to_expire"]
        is_valid = (
            0
            if certificate_status(info, warn_days) in ("EXPIRED", "INVALID DATES")
            else 1
        )
        up.append(f'certinspect_up{{target="{label}"}} 1')
        expiry.append(f'certinspect_cert_expiry_days{{target="{label}"}} {days}')
        valid.append(f'certinspect_cert_valid{{target="{label}"}} {is_valid}')

    for target, _ in errors:
        label = _prometheus_label(target or "")
        up.append(f'certinspect_up{{target="{label}"}} 0')

    lines = [
        "# HELP certinspect_up Whether the target could be inspected (1) or not (0).",
        "# TYPE certinspect_up gauge",
        *up,
        "# HELP certinspect_cert_expiry_days Days until the certificate expires.",
        "# TYPE certinspect_cert_expiry_days gauge",
        *expiry,
        "# HELP certinspect_cert_valid Whether the certificate is within its validity window (1) or not (0).",
        "# TYPE certinspect_cert_valid gauge",
        *valid,
    ]
    return "\n".join(lines)
