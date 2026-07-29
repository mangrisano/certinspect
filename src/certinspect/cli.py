"""Command-line entry point.

Wire together fetch -> parser -> formatter, reading the CLI arguments.

It fetches a certificate from one or more hosts (or reads a local file),
analyzes it, prints the result as human-readable text or JSON, and exits
with a status code reflecting the worst certificate state found.
"""

import argparse
import sys
import ssl
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, fields
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
    cab_forum_max_validity,
    certificate_status,
    chain_expiry_warnings,
    hostname_matches,
    missing_san_names,
    chain_summary,
    pin_matches,
    policy_violations,
    POLICY_PROFILES,
    to_pem,
)
from certinspect.formatter import (
    format_csv,
    format_fields,
    format_human,
    format_json,
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
    "NOT YET VALID": 4,
}


@dataclass(frozen=True)
class InspectOptions:
    """Per-run inspection options shared by every target in a batch.

    Bundles the flags that do not change from one target to the next so they
    can be threaded through ``_inspect`` as a single value instead of a long
    keyword list. Only ``target`` and ``port`` vary per target and stay
    explicit arguments.
    """

    file: str | None = None
    days: int = 30
    critical_days: int | None = None
    export: str | None = None
    timeout: float = 5.0
    verify: bool = False
    chain: bool = False
    pin: str | None = None
    starttls: str | None = None
    cafile: str | None = None
    capath: str | None = None
    servername: str | None = None
    expect_san: list[str] | None = None
    not_after_max: int | None = None
    cab_forum: bool = False
    min_key_size: int | None = None
    fail_weak: bool = False
    require_sct: bool = False
    require_must_staple: bool = False
    min_tls_version: str | None = None
    client_cert: str | None = None
    client_key: str | None = None
    proxy: str | None = None
    no_proxy: bool = False

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "InspectOptions":
        """Build the options from parsed CLI arguments.

        Every field name matches its argparse destination, so the mapping stays
        in one place: adding a field here (and the matching argument) is enough.
        """
        return cls(**{f.name: getattr(args, f.name) for f in fields(cls)})


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
            "instead of a host; use '-' to read the certificate from standard "
            "input."
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
    # --json, --csv and --exporter select the output format and are mutually
    # exclusive; argparse rejects any combination for us (exit code 2).
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument(
        "--json",
        action="store_true",
        help="Output the result as JSON instead of human-readable text.",
    )
    output_group.add_argument(
        "--field",
        action="append",
        metavar="NAME",
        dest="field",
        help=(
            "Print only the given field(s), one tab-separated line per target "
            "(e.g. --field days_to_expire). Repeat for several fields; use "
            "'target' for the inspected host. Handy for scripting without "
            "piping --json through a JSON tool."
        ),
    )
    output_group.add_argument(
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
        "--client-cert",
        metavar="PATH",
        dest="client_cert",
        help=(
            "Present a client certificate (PEM) for mutual-TLS endpoints (host "
            "targets only). If the file does not also contain the private key, "
            "pass it with --client-key."
        ),
    )
    parser.add_argument(
        "--client-key",
        metavar="PATH",
        dest="client_key",
        help=(
            "Private key (PEM) for --client-cert, when it is stored separately "
            "from the certificate."
        ),
    )
    parser.add_argument(
        "--proxy",
        metavar="URL",
        help=(
            "Tunnel the connection through an HTTP CONNECT proxy, e.g. "
            "http://proxy:8080 or http://user:pass@proxy:8080 (host targets "
            "only). With no --proxy the environment proxy (HTTPS_PROXY, honouring "
            "NO_PROXY) is used automatically, like curl."
        ),
    )
    parser.add_argument(
        "--no-proxy",
        action="store_true",
        dest="no_proxy",
        help=(
            "Force a direct connection, ignoring any proxy set in the "
            "environment. Mutually exclusive with --proxy."
        ),
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
        "--profile",
        choices=tuple(POLICY_PROFILES),
        default=None,
        help=(
            "Apply a named bundle of the opt-in policy checks (exit code 9) in "
            "one go. Intensity ladder, not an official standard: 'lenient' = "
            "TLS >= 1.2 and fail on weak crypto; 'standard' adds a 2048-bit "
            "minimum key; 'strict' = TLS >= 1.3, 2048-bit key, weak-crypto "
            "failure, required Certificate Transparency SCTs and the CA/Browser "
            "Forum validity cap. Any explicit flag overrides the profile; the "
            "TLS-version part applies to host targets only. Passing a profile "
            "is not a compliance attestation."
        ),
    )
    # --not-after-max and --cab-forum both cap the total validity; the latter
    # resolves to the current CA/Browser Forum maximum, so they are mutually
    # exclusive (argparse rejects any combination with exit code 2).
    validity_group = parser.add_mutually_exclusive_group()
    validity_group.add_argument(
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
    validity_group.add_argument(
        "--cab-forum",
        action="store_true",
        dest="cab_forum",
        help=(
            "Fail (exit code 9) when the total validity exceeds the CA/Browser "
            "Forum maximum in effect today (398 days now, then 200, 100 and 47 "
            "on 2026/2027/2029-03-15). Date-aware shorthand for --not-after-max."
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
        "--require-sct",
        action="store_true",
        dest="require_sct",
        help=(
            "Fail (exit code 9) when the certificate embeds no Signed "
            "Certificate Timestamps (Certificate Transparency). Only the SCTs "
            "embedded in the certificate are checked, not those delivered over "
            "the TLS handshake or OCSP. Opt-in policy check."
        ),
    )
    parser.add_argument(
        "--require-must-staple",
        action="store_true",
        dest="require_must_staple",
        help=(
            "Fail (exit code 9) when the certificate lacks the OCSP Must-Staple "
            "extension (RFC 7633 TLS Feature status_request). Opt-in policy "
            "check."
        ),
    )
    parser.add_argument(
        "--min-tls-version",
        choices=("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"),
        default=None,
        dest="min_tls_version",
        help=(
            "Fail (exit code 9) when the connection negotiates a TLS version "
            "older than this (e.g. TLSv1.2). Opt-in policy check; host targets "
            "only, as it needs a live handshake."
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
    output_group.add_argument(
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
    parser.add_argument(
        "--exit-zero",
        action="store_true",
        dest="exit_zero",
        help=(
            "Always exit with code 0, even on problems or fetch errors. "
            "Report-only mode for dashboards/CI that read the output rather "
            "than the exit code."
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
    opts: InspectOptions,
) -> tuple[bytes, dict | None]:
    """Return (raw certificate bytes, connection info) for one source.

    Connection info is None for local files (no live TLS handshake).
    """
    if opts.file:
        if opts.file == "-":
            return sys.stdin.buffer.read(), None
        with open(opts.file, "rb") as f:
            return f.read(), None
    kwargs: dict = {"starttls": opts.starttls, "servername": opts.servername}
    if opts.client_cert:
        kwargs["client_cert"] = opts.client_cert
        kwargs["client_key"] = opts.client_key
    if opts.proxy:
        kwargs["proxy"] = opts.proxy
    if opts.no_proxy:
        kwargs["no_proxy"] = True
    return get_server_cert(target, port, opts.timeout, **kwargs)


def _inspect(
    target: str | None,
    port: int,
    opts: InspectOptions,
) -> tuple[dict, int]:
    """Inspect one source and return its (info, exit_code).

    The hostname match (and its exit code 5) only applies to host targets;
    with --file it is left as None. When ``servername`` is set it overrides
    both the SNI hostname and the name the hostname match is checked against.
    Chain verification (exit code 6) is only performed for host targets when
    ``verify`` is set. A failed ``pin`` check yields exit code 7. When
    ``expect_san`` names are not all covered by the certificate's SAN the exit
    code is 8. The opt-in policy checks (``not_after_max``/``cab_forum``,
    ``min_key_size``, ``fail_weak``, ``require_sct``, ``require_must_staple``,
    ``min_tls_version``) yield exit code 9 when any is violated.
    """
    der, conn = _fetch_source(target, port, opts)
    cert = load_certificate(der)
    info = analyze(cert)
    if conn:
        info["tls_version"] = conn["tls_version"]
        info["cipher"] = conn["cipher"]
    if opts.export:
        with open(opts.export, "wb") as f:
            f.write(to_pem(cert))
    check_name = opts.servername or target
    info["hostname_match"] = hostname_matches(info, check_name) if check_name else None

    info["status"] = certificate_status(info, opts.days, opts.critical_days)
    code = EXIT_BY_STATUS[info["status"]]
    if info["hostname_match"] is False:
        code = 5

    # The verified chain (when available) is the most accurate source for the
    # intermediates actually used; fall back to the chain presented by the
    # server. Either way the leaf is skipped by chain_expiry_warnings.
    chain_certs: list = []

    if opts.verify and target:
        verify_kwargs: dict = {
            "starttls": opts.starttls,
            "cafile": opts.cafile,
            "capath": opts.capath,
            "servername": opts.servername,
        }
        if opts.client_cert:
            verify_kwargs["client_cert"] = opts.client_cert
            verify_kwargs["client_key"] = opts.client_key
        if opts.proxy:
            verify_kwargs["proxy"] = opts.proxy
        if opts.no_proxy:
            verify_kwargs["no_proxy"] = True
        trusted, reason, verified = verify_chain(
            target,
            port,
            opts.timeout,
            **verify_kwargs,
        )
        info["chain_trusted"] = trusted
        info["chain_error"] = reason
        if not trusted:
            code = 6

        # Prefer the issuer from the verified chain; fall back to AIA download.
        issuer = verified[1] if len(verified) > 1 else None
        revocation, detail = check_revocation(cert, opts.timeout, issuer=issuer)
        info["revocation_status"] = revocation
        info["revocation_detail"] = detail
        if revocation == "REVOKED":
            code = 6
        chain_certs = verified

    if not chain_certs and conn:
        chain_certs = conn.get("chain") or []

    chain_warnings = chain_expiry_warnings(chain_certs, opts.days)
    if chain_warnings:
        info["chain_warnings"] = chain_warnings

    if opts.chain:
        presented = (conn.get("chain") if conn else None) or [cert]
        info["chain"] = [chain_summary(c) for c in presented]

    if opts.pin:
        info["pin_match"] = pin_matches(info, opts.pin)
        if not info["pin_match"]:
            code = 7

    if opts.expect_san:
        missing = missing_san_names(info, opts.expect_san)
        info["expected_san_missing"] = missing
        if missing:
            code = 8

    if (
        opts.not_after_max is not None
        or opts.cab_forum
        or opts.min_key_size is not None
        or opts.fail_weak
        or opts.require_sct
        or opts.require_must_staple
        or opts.min_tls_version is not None
    ):
        not_after_max = opts.not_after_max
        if opts.cab_forum:
            not_after_max = cab_forum_max_validity()
        violations = policy_violations(
            info,
            not_after_max=not_after_max,
            min_key_size=opts.min_key_size,
            fail_weak=opts.fail_weak,
            require_sct=opts.require_sct,
            require_must_staple=opts.require_must_staple,
            min_tls_version=opts.min_tls_version,
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
    fields: list[str] | None = None,
    errors: list[tuple[str | None, str]] = (),
) -> int | None:
    """Print the collected results and return an optional exit-code override.

    With ``exporter`` set, render monitoring output: 'nagios' returns its
    plugin exit code (the override), 'prometheus' returns None. Otherwise
    print the selected ``fields`` (tab-separated), JSON, CSV, or human text;
    ``quiet`` keeps only results with a non-zero exit code and ``max_days``
    keeps only those expiring within that many days. ``sort`` reorders the kept
    results ('host' or 'expiry'). All three affect the display only, never the
    exit code. ``summary`` prints a one-line tally to stderr, counting every
    target before filtering.
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

    if fields:
        text = format_fields(results, fields)
        if text:
            print(text)
    elif as_csv:
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
        print(format_json([info for _, info, _ in results]))
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


def _apply_profile(args: argparse.Namespace) -> None:
    """Merge the selected --profile preset into the parsed arguments.

    A profile is a named bundle of the opt-in policy checks. Its values only
    fill in options the user left at their default, so any explicit flag on the
    command line overrides the profile. The profile's ``--min-tls-version`` is
    skipped for --file targets, which have no live handshake to measure, and an
    explicit ``--not-after-max`` takes precedence over a profile's CA/Browser
    Forum cap (keeping the two validity checks mutually exclusive).
    """
    if not args.profile:
        return
    preset = POLICY_PROFILES[args.profile]
    if "min_key_size" in preset and args.min_key_size is None:
        args.min_key_size = preset["min_key_size"]
    if "min_tls_version" in preset and args.min_tls_version is None and not args.file:
        args.min_tls_version = preset["min_tls_version"]
    for name in ("fail_weak", "require_sct", "require_must_staple"):
        if preset.get(name):
            setattr(args, name, True)
    if preset.get("cab_forum") and args.not_after_max is None:
        args.cab_forum = True


def main() -> None:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args()
    _apply_profile(args)

    if len(args.csv_delimiter) != 1:
        parser.error("--csv-delimiter must be a single character.")
    if args.critical_days is not None and args.critical_days > args.days:
        parser.error("--critical-days must be less than or equal to --days.")
    if (args.cafile or args.capath) and not args.verify:
        parser.error("--cafile/--capath require --verify.")
    if args.servername and args.file:
        parser.error("--servername applies to host targets, not --file.")
    if args.min_tls_version and args.file:
        parser.error("--min-tls-version applies to host targets, not --file.")
    if args.client_key and not args.client_cert:
        parser.error("--client-key requires --client-cert.")
    if args.proxy and args.no_proxy:
        parser.error("--proxy and --no-proxy are mutually exclusive.")
    if (args.client_cert or args.proxy or args.no_proxy) and args.file:
        parser.error(
            "--client-cert/--proxy/--no-proxy apply to host targets, not --file."
        )

    extra_targets = []
    if args.input:
        # An unreadable --input file (missing, no permission) is a runtime error
        # like an unreachable host: report it cleanly with exit code 1 instead
        # of letting the OSError surface as a traceback.
        try:
            extra_targets = _read_targets(args.input)
        except OSError as err:
            print(f"error: {err}", file=sys.stderr)
            sys.exit(1)
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

    opts = InspectOptions.from_args(args)

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
            info, code = _inspect(target, port, opts)
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
        fields=args.field,
        errors=errors,
    )
    if args.exit_zero:
        sys.exit(0)
    sys.exit(override if override is not None else max(codes, default=0))


if __name__ == "__main__":
    main()
