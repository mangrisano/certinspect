"""Command-line entry point.

Wire together fetch -> parser -> formatter, reading the CLI arguments.

It fetches a certificate from one or more hosts (or reads a local file),
analyzes it, prints the result as human-readable text or JSON, and exits
with a status code reflecting the worst certificate state found.
"""

import argparse
import json
import sys
import ssl
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit
from certinspect import __version__
from certinspect.fetch import (
    STARTTLS_PORTS,
    check_revocation,
    get_server_cert,
    verify_chain,
)
from certinspect.parser import (
    load_certificate,
    analyze,
    certificate_status,
    hostname_matches,
    chain_summary,
    pin_matches,
    to_pem,
)
from certinspect.formatter import format_human, format_nagios, format_prometheus

# Exit codes reflecting the certificate status, kept distinct from
# argparse's usage error (2) and the generic runtime error (1).
EXIT_BY_STATUS = {
    "VALID": 0,
    "EXPIRING": 3,
    "EXPIRED": 4,
    "INVALID DATES": 4,
}


def build_parser() -> argparse.ArgumentParser:
    """Build and return the ArgumentParser."""
    parser = argparse.ArgumentParser(
        prog="certinspect",
        description="Inspect a TLS certificate from a host or a local file.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "target",
        nargs="*",
        help=(
            "One or more domain names to inspect (e.g. example.com). "
            "Omit when using --file."
        ),
    )
    parser.add_argument(
        "--file",
        help=(
            "Path to a local certificate file (PEM or DER) to inspect "
            "instead of a host."
        ),
    )
    parser.add_argument(
        "--port",
        type=int,
        default=443,
        help="TCP port to connect to (default: 443).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Connection timeout in seconds (default: 5).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output the result as JSON instead of human-readable text.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only print certificates that have a problem.",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help=(
            "Verify the certificate chain against the system trust store "
            "(host targets only)."
        ),
    )
    parser.add_argument(
        "--chain",
        action="store_true",
        help="Show the certificate chain presented by the server.",
    )
    parser.add_argument(
        "--pin",
        metavar="SHA256",
        help=(
            "Expected SHA-256 fingerprint; exit with code 7 if it does not "
            "match (colons and case are ignored)."
        ),
    )
    parser.add_argument(
        "--input",
        metavar="PATH",
        help=(
            "Read additional targets from a file (one per line, '#' comments "
            "allowed); use '-' to read from standard input."
        ),
    )
    parser.add_argument(
        "--days",
        type=int,
        default=30,
        help=("Warn if the certificate expires within this many days (default: 30)."),
    )
    parser.add_argument(
        "--export",
        metavar="PATH",
        help="Save the inspected certificate as a PEM file at PATH.",
    )
    parser.add_argument(
        "--starttls",
        choices=tuple(STARTTLS_PORTS),
        help=(
            "Upgrade a plaintext connection to TLS before inspecting (host "
            "targets only). When --port is left at its default, the protocol's "
            "standard port is used (smtp=587, imap=143, pop3=110, ftp=21)."
        ),
    )
    parser.add_argument(
        "--exporter",
        choices=("nagios", "prometheus"),
        help=(
            "Emit machine-readable monitoring output instead of the normal "
            "report: a Nagios/Icinga plugin line per target (exit code follows "
            "the plugin convention) or Prometheus textfile metrics. Ignores "
            "--quiet so every target is always reported."
        ),
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=1,
        metavar="N",
        help=(
            "Number of hosts to inspect in parallel in batch mode "
            "(default: 1). Output order is preserved regardless of N."
        ),
    )

    return parser


def _split_target(raw: str, default_port: int) -> tuple[str, int]:
    """Normalize a target into ``(host, port)``.

    Accepts a bare hostname, a ``host:port`` pair, or a full URL (the scheme
    and any path are ignored). An explicit port in the target overrides
    ``default_port``.
    """
    spec = raw if "://" in raw else f"//{raw}"
    parts = urlsplit(spec)
    return parts.hostname or raw, parts.port or default_port


def _fetch_source(
    target: str | None,
    port: int,
    file: str | None,
    timeout: float,
    starttls: str | None = None,
) -> tuple[bytes, dict | None]:
    """Return (raw certificate bytes, connection info) for one source.

    Connection info is None for local files (no live TLS handshake).
    """
    if file:
        with open(file, "rb") as f:
            return f.read(), None
    return get_server_cert(target, port, timeout, starttls=starttls)


def _inspect(
    target: str | None,
    *,
    port: int,
    file: str | None,
    days: int,
    export: str | None,
    timeout: float,
    verify: bool,
    chain: bool,
    pin: str | None,
    starttls: str | None = None,
) -> tuple[dict, int]:
    """Inspect one source and return its (info, exit_code).

    The hostname match (and its exit code 5) only applies to host targets;
    with --file it is left as None. Chain verification (exit code 6) is only
    performed for host targets when ``verify`` is set. A failed ``pin`` check
    yields exit code 7.
    """
    der, conn = _fetch_source(target, port, file, timeout, starttls=starttls)
    cert = load_certificate(der)
    info = analyze(cert)
    if conn:
        info["tls_version"] = conn["tls_version"]
        info["cipher"] = conn["cipher"]
    if export:
        with open(export, "wb") as f:
            f.write(to_pem(cert))
    info["hostname_match"] = hostname_matches(info, target) if target else None

    code = EXIT_BY_STATUS[certificate_status(info, days)]
    if info["hostname_match"] is False:
        code = 5

    if verify and target:
        trusted, reason, verified = verify_chain(
            target, port, timeout, starttls=starttls
        )
        info["chain_trusted"] = trusted
        info["chain_error"] = reason
        if not trusted:
            code = 6

        # Prefer the issuer from the verified chain; fall back to AIA download.
        issuer = verified[1] if len(verified) > 1 else None
        revocation, detail = check_revocation(cert, timeout, issuer=issuer)
        info["revocation_status"] = revocation
        info["revocation_detail"] = detail
        if revocation == "REVOKED":
            code = 6

    if chain:
        presented = (conn.get("chain") if conn else None) or [cert]
        info["chain"] = [chain_summary(c) for c in presented]

    if pin:
        info["pin_match"] = pin_matches(info, pin)
        if not info["pin_match"]:
            code = 7
    return info, code


def _render(
    results: list[tuple[str | None, dict, int]],
    *,
    as_json: bool,
    days: int,
    quiet: bool,
    exporter: str | None = None,
    errors: list[tuple[str | None, str]] = (),
) -> int | None:
    """Print the collected results and return an optional exit-code override.

    With ``exporter`` set, render monitoring output: 'nagios' returns its
    plugin exit code (the override), 'prometheus' returns None. Otherwise
    print JSON (always a list) or human text; when ``quiet`` is set, only
    results with a non-zero exit code are shown.
    """
    if exporter == "nagios":
        text, code = format_nagios(results, errors, warn_days=days)
        print(text)
        return code
    if exporter == "prometheus":
        print(format_prometheus(results, errors, warn_days=days))
        return None

    if quiet:
        results = [r for r in results if r[2] != 0]

    if as_json:
        print(json.dumps([info for _, info, _ in results], indent=2, default=str))
        return None

    blocks = []
    for target, info, _ in results:
        text = format_human(info, warn_days=days)
        blocks.append(f"=== {target} ===\n{text}" if target else text)
    if blocks:
        print("\n\n".join(blocks))
    return None


def _read_targets(path: str) -> list[str]:
    """Read targets from a file (or stdin when path is '-').

    One target per line; blank lines and '#' comments are ignored.
    """
    lines = sys.stdin if path == "-" else open(path, encoding="utf-8")
    try:
        targets = []
        for line in lines:
            entry = line.strip()
            if entry and not entry.startswith("#"):
                targets.append(entry)
        return targets
    finally:
        if path != "-":
            lines.close()


def main() -> None:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args()

    if args.exporter and args.json:
        parser.error("--exporter and --json cannot be used together.")

    extra_targets = _read_targets(args.input) if args.input else []
    if not args.target and not extra_targets and not args.file:
        parser.error("There is no target or no file to inspect.")

    # A single --file source has no host; otherwise iterate over the targets.
    if args.file:
        targets: list[str | None] = [None]
    else:
        targets = [*args.target, *extra_targets]

    # With STARTTLS, fall back to the protocol's standard port unless the user
    # passed --port explicitly (i.e. it differs from the 443 default).
    default_port = args.port
    if args.starttls and default_port == 443:
        default_port = STARTTLS_PORTS[args.starttls]

    def _run(raw_target: str | None) -> tuple[str | None, tuple | None, str | None]:
        """Inspect one target, returning (raw_target, payload, error).

        ``payload`` is ``(target, info, code)`` on success and None on failure,
        in which case ``error`` carries the message. Runs in worker threads, so
        it must not perform any I/O on shared streams.
        """
        target, port = raw_target, default_port
        try:
            if raw_target is not None:
                target, port = _split_target(raw_target, default_port)
            info, code = _inspect(
                target,
                port=port,
                file=args.file,
                days=args.days,
                export=args.export,
                timeout=args.timeout,
                verify=args.verify,
                chain=args.chain,
                pin=args.pin,
                starttls=args.starttls,
            )
        except (OSError, ssl.SSLError, ValueError) as err:
            return raw_target, None, str(err)
        return raw_target, (target, info, code), None

    # Inspect in parallel when asked; ThreadPoolExecutor.map preserves order.
    workers = max(1, args.concurrency)
    if workers > 1 and len(targets) > 1:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            outcomes = list(pool.map(_run, targets))
    else:
        outcomes = [_run(t) for t in targets]

    results: list[tuple[str | None, dict, int]] = []
    errors: list[tuple[str | None, str]] = []
    codes: list[int] = []
    for raw_target, payload, err in outcomes:
        if err is not None:
            if not args.exporter:
                label = f"{raw_target}: " if raw_target else ""
                print(f"error: {label}{err}", file=sys.stderr)
            errors.append((raw_target, err))
            codes.append(1)
            continue
        results.append(payload)
        codes.append(payload[2])

    override = _render(
        results,
        as_json=args.json,
        days=args.days,
        quiet=args.quiet,
        exporter=args.exporter,
        errors=errors,
    )
    sys.exit(override if override is not None else max(codes, default=0))


if __name__ == "__main__":
    main()
