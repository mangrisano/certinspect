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
    chain_expiry_warnings,
    hostname_matches,
    missing_san_names,
    chain_summary,
    pin_matches,
    policy_violations,
    to_pem,
)
from certinspect.formatter import (
    format_csv,
    format_human,
    format_nagios,
    format_prometheus,
    format_summary,
)

# Exit codes reflecting the certificate status, kept distinct from
# argparse's usage error (2) and the generic runtime error (1).
EXIT_BY_STATUS = {
    "VALID": 0,
    "EXPIRING": 3,
    "CRITICAL": 4,
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
        "--csv",
        action="store_true",
        help=(
            "Output the results as CSV (one row per target, with a header), "
            "convenient for spreadsheets."
        ),
    )
    parser.add_argument(
        "--csv-delimiter",
        default=",",
        metavar="SEP",
        help=(
            "Field separator for --csv (default: ','). Use ';' for Numbers or "
            "Excel in locales that expect it (e.g. Italian)."
        ),
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
        "--cafile",
        metavar="PATH",
        help=(
            "Verify the chain against this CA bundle (PEM) instead of the "
            "system trust store. Requires --verify; useful behind an "
            "internal/private PKI."
        ),
    )
    parser.add_argument(
        "--capath",
        metavar="DIR",
        help=(
            "Verify the chain against the hashed CA certificates in this "
            "directory (OpenSSL c_rehash layout) instead of the system trust "
            "store. Requires --verify; may be combined with --cafile."
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
        "--servername",
        metavar="NAME",
        help=(
            "Override the SNI hostname sent in the TLS handshake (host targets "
            "only). Lets you reach a specific backend by IP or DNS name while "
            "presenting the virtual host a load balancer routes on; the "
            "hostname match is checked against this name instead of the target."
        ),
    )
    parser.add_argument(
        "--expect-san",
        metavar="NAME",
        action="append",
        dest="expect_san",
        help=(
            "Assert that the certificate's SAN covers NAME (wildcards honored); "
            "exit with code 8 if any expected name is missing. Repeat the flag "
            "to require several names. Works for host and --file targets."
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
        "--critical-days",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Escalate to CRITICAL (exit code 4) when the certificate expires "
            "within this many days. Must be <= --days; lets monitoring "
            "distinguish a warning window from a critical one."
        ),
    )
    parser.add_argument(
        "--not-after-max",
        type=int,
        default=None,
        metavar="N",
        dest="not_after_max",
        help=(
            "Fail (exit code 9) when the certificate's total validity exceeds N "
            "days. Use 398 to enforce the current CA/Browser Forum maximum. "
            "Opt-in policy check; works for host and --file targets."
        ),
    )
    parser.add_argument(
        "--min-key-size",
        type=int,
        default=None,
        metavar="N",
        dest="min_key_size",
        help=(
            "Fail (exit code 9) when the public key is smaller than N bits "
            "(e.g. 2048 for RSA). Opt-in policy check."
        ),
    )
    parser.add_argument(
        "--fail-weak",
        action="store_true",
        dest="fail_weak",
        help=(
            "Turn the weak-crypto warnings (small key, SHA-1/MD5 signature) "
            "into a hard failure (exit code 9) instead of a mere warning."
        ),
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
    parser.add_argument(
        "--max-days",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Only show certificates that expire within N days (already-expired "
            "ones are always shown). Filters the output only; the exit code "
            "still reflects every inspected target."
        ),
    )
    parser.add_argument(
        "--sort",
        choices=("host", "expiry"),
        default=None,
        help=(
            "Sort the output: 'host' alphabetically by target, 'expiry' by "
            "days left (soonest first). Affects the display only, not the "
            "exit code."
        ),
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help=(
            "Print a one-line tally (valid/expiring/expired/errors) to stderr "
            "after the report. Counts every inspected target, ignoring "
            "--quiet/--max-days filtering."
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
    servername: str | None = None,
) -> tuple[bytes, dict | None]:
    """Return (raw certificate bytes, connection info) for one source.

    Connection info is None for local files (no live TLS handshake).
    """
    if file:
        with open(file, "rb") as f:
            return f.read(), None
    return get_server_cert(
        target, port, timeout, starttls=starttls, servername=servername
    )


def _inspect(
    target: str | None,
    *,
    port: int,
    file: str | None,
    days: int,
    critical_days: int | None,
    export: str | None,
    timeout: float,
    verify: bool,
    chain: bool,
    pin: str | None,
    starttls: str | None = None,
    cafile: str | None = None,
    capath: str | None = None,
    servername: str | None = None,
    expect_san: list[str] | None = None,
    not_after_max: int | None = None,
    min_key_size: int | None = None,
    fail_weak: bool = False,
) -> tuple[dict, int]:
    """Inspect one source and return its (info, exit_code).

    The hostname match (and its exit code 5) only applies to host targets;
    with --file it is left as None. When ``servername`` is set it overrides
    both the SNI hostname and the name the hostname match is checked against.
    Chain verification (exit code 6) is only performed for host targets when
    ``verify`` is set. A failed ``pin`` check yields exit code 7. When
    ``expect_san`` names are not all covered by the certificate's SAN the exit
    code is 8. The opt-in policy checks (``not_after_max``, ``min_key_size``,
    ``fail_weak``) yield exit code 9 when any is violated.
    """
    der, conn = _fetch_source(
        target, port, file, timeout, starttls=starttls, servername=servername
    )
    cert = load_certificate(der)
    info = analyze(cert)
    if conn:
        info["tls_version"] = conn["tls_version"]
        info["cipher"] = conn["cipher"]
    if export:
        with open(export, "wb") as f:
            f.write(to_pem(cert))
    check_name = servername or target
    info["hostname_match"] = hostname_matches(info, check_name) if check_name else None

    code = EXIT_BY_STATUS[certificate_status(info, days, critical_days)]
    if info["hostname_match"] is False:
        code = 5

    # The verified chain (when available) is the most accurate source for the
    # intermediates actually used; fall back to the chain presented by the
    # server. Either way the leaf is skipped by chain_expiry_warnings.
    chain_certs: list = []

    if verify and target:
        trusted, reason, verified = verify_chain(
            target,
            port,
            timeout,
            starttls=starttls,
            cafile=cafile,
            capath=capath,
            servername=servername,
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
        chain_certs = verified

    if not chain_certs and conn:
        chain_certs = conn.get("chain") or []

    chain_warnings = chain_expiry_warnings(chain_certs, days)
    if chain_warnings:
        info["chain_warnings"] = chain_warnings

    if chain:
        presented = (conn.get("chain") if conn else None) or [cert]
        info["chain"] = [chain_summary(c) for c in presented]

    if pin:
        info["pin_match"] = pin_matches(info, pin)
        if not info["pin_match"]:
            code = 7

    if expect_san:
        missing = missing_san_names(info, expect_san)
        info["expected_san_missing"] = missing
        if missing:
            code = 8

    if not_after_max is not None or min_key_size is not None or fail_weak:
        violations = policy_violations(
            info,
            not_after_max=not_after_max,
            min_key_size=min_key_size,
            fail_weak=fail_weak,
        )
        info["policy_violations"] = violations
        if violations:
            code = 9
    return info, code


def _render(
    results: list[tuple[str | None, dict, int]],
    *,
    as_json: bool,
    days: int,
    quiet: bool,
    as_csv: bool = False,
    csv_delimiter: str = ",",
    critical_days: int | None = None,
    max_days: int | None = None,
    sort: str | None = None,
    summary: bool = False,
    exporter: str | None = None,
    errors: list[tuple[str | None, str]] = (),
) -> int | None:
    """Print the collected results and return an optional exit-code override.

    With ``exporter`` set, render monitoring output: 'nagios' returns its
    plugin exit code (the override), 'prometheus' returns None. Otherwise
    print JSON, CSV, or human text; ``quiet`` keeps only results with a
    non-zero exit code and ``max_days`` keeps only those expiring within that
    many days. ``sort`` reorders the kept results ('host' or 'expiry'). All
    three affect the display only, never the exit code. ``summary`` prints a
    one-line tally to stderr, counting every target before filtering.
    """
    if exporter == "nagios":
        text, code = format_nagios(
            results, errors, warn_days=days, critical_days=critical_days
        )
        print(text)
        return code
    if exporter == "prometheus":
        print(format_prometheus(results, errors, warn_days=days))
        return None

    # Computed from the full result set, before --quiet/--max-days filtering.
    summary_line = (
        format_summary(results, errors, warn_days=days, critical_days=critical_days)
        if summary
        else None
    )

    if quiet:
        results = [r for r in results if r[2] != 0]
    if max_days is not None:
        results = [r for r in results if r[1]["days_to_expire"] <= max_days]
    if sort == "host":
        results = sorted(results, key=lambda r: r[0] or "")
    elif sort == "expiry":
        results = sorted(results, key=lambda r: r[1]["days_to_expire"])

    if as_csv:
        print(
            format_csv(
                results,
                warn_days=days,
                delimiter=csv_delimiter,
                critical_days=critical_days,
            ),
            end="",
        )
    elif as_json:
        print(json.dumps([info for _, info, _ in results], indent=2, default=str))
    else:
        blocks = []
        for target, info, _ in results:
            text = format_human(info, warn_days=days, critical_days=critical_days)
            blocks.append(f"=== {target} ===\n{text}" if target else text)
        if blocks:
            print("\n\n".join(blocks))

    if summary_line:
        print(summary_line, file=sys.stderr)
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
    if args.csv and args.json:
        parser.error("--csv and --json cannot be used together.")
    if args.csv and args.exporter:
        parser.error("--csv and --exporter cannot be used together.")
    if len(args.csv_delimiter) != 1:
        parser.error("--csv-delimiter must be a single character.")
    if args.critical_days is not None and args.critical_days > args.days:
        parser.error("--critical-days must be less than or equal to --days.")
    if (args.cafile or args.capath) and not args.verify:
        parser.error("--cafile/--capath require --verify.")
    if args.servername and args.file:
        parser.error("--servername applies to host targets, not --file.")

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
                critical_days=args.critical_days,
                export=args.export,
                timeout=args.timeout,
                verify=args.verify,
                chain=args.chain,
                pin=args.pin,
                starttls=args.starttls,
                cafile=args.cafile,
                capath=args.capath,
                servername=args.servername,
                expect_san=args.expect_san,
                not_after_max=args.not_after_max,
                min_key_size=args.min_key_size,
                fail_weak=args.fail_weak,
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
        as_csv=args.csv,
        csv_delimiter=args.csv_delimiter,
        critical_days=args.critical_days,
        max_days=args.max_days,
        sort=args.sort,
        summary=args.summary,
        exporter=args.exporter,
        errors=errors,
    )
    sys.exit(override if override is not None else max(codes, default=0))


if __name__ == "__main__":
    main()
