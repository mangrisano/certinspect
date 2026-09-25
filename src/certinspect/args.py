"""Command-line argument parser definition.

Builds the full argparse parser for certinspect. Kept separate from the
orchestration in ``cli`` so the wall of flag declarations does not crowd the
run logic; the completion and --config machinery introspect this parser.
"""

import argparse

from certinspect import __version__
from certinspect.config import DEFAULT_CONFIG_PATH
from certinspect.fetch import STARTTLS_PORTS
from certinspect.parser import POLICY_PROFILES


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
        "--config",
        metavar="PATH",
        help=(
            f"TOML file of default option values (keys use the argparse "
            f"destination name, e.g. 'days = 14' or 'verify = false'); an "
            f"explicit command-line flag always overrides it. Without "
            f"--config, {DEFAULT_CONFIG_PATH} is loaded automatically if it "
            "exists."
        ),
    )
    parser.add_argument(
        "--print-completion",
        choices=("bash", "zsh"),
        dest="print_completion",
        help=(
            "Print a shell completion script for bash or zsh to stdout, then "
            "exit; e.g. 'certinspect --print-completion bash > "
            "/etc/bash_completion.d/certinspect'. Generated from this parser, "
            "so it always matches the installed version's flags."
        ),
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
        action="append",
        help=(
            "Path to a local certificate file (PEM or DER) to inspect "
            "instead of a host; use '-' to read the certificate from standard "
            "input. Repeat the flag to inspect several files in one run (each "
            "is reported separately); at most one may be '-'. Cannot be "
            "combined with host targets."
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
        "--connect-timeout",
        type=float,
        default=None,
        dest="connect_timeout",
        help="TCP connect timeout in seconds (default: --timeout).",
    )
    parser.add_argument(
        "--read-timeout",
        type=float,
        default=None,
        dest="read_timeout",
        help="Handshake/read timeout in seconds (default: --timeout).",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=0,
        help="Retry transient connection failures this many times (default: 0).",
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
        "--schema",
        type=int,
        choices=[1, 2],
        default=2,
        help=(
            "JSON schema version for --json (default: 2). Version 2 nests fields "
            "by domain, uses ISO 8601 dates, stringifies the serial number and "
            "wraps results in a versioned object; version 1 is the legacy flat "
            "array."
        ),
    )
    verify_group = parser.add_mutually_exclusive_group()
    verify_group.add_argument(
        "--verify",
        dest="verify",
        action="store_true",
        default=True,
        help=(
            "Verify the certificate chain against the system trust store "
            "(the default): a verified handshake plus OCSP/CRL revocation for a "
            "host, or the bundle validated offline for --file. Kept for "
            "explicitness; verification is on unless --no-verify is given."
        ),
    )
    verify_group.add_argument(
        "--no-verify",
        dest="verify",
        action="store_false",
        help=(
            "Skip chain verification (and revocation for hosts); only inspect "
            "the certificate itself."
        ),
    )
    parser.add_argument(
        "--cafile",
        metavar="PATH",
        help=(
            "Verify the chain against this CA bundle (PEM) instead of the "
            "system trust store; useful behind an internal/private PKI. "
            "Incompatible with --no-verify."
        ),
    )
    parser.add_argument(
        "--capath",
        metavar="DIR",
        help=(
            "Verify the chain against the hashed CA certificates in this "
            "directory (OpenSSL c_rehash layout) instead of the system trust "
            "store. Incompatible with --no-verify; may be combined with --cafile."
        ),
    )
    parser.add_argument(
        "--chain",
        action="store_true",
        help=(
            "Show the certificate chain: the one presented by the server for a "
            "host, or every certificate in the bundle for --file."
        ),
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
        "--discover",
        metavar="DOMAIN",
        action="append",
        help=(
            "Discover hostnames from Certificate Transparency logs (crt.sh) for "
            "DOMAIN and inspect each one, surfacing forgotten or shadow "
            "certificates. Repeat the flag for several domains. Host targets "
            "only; the crt.sh query uses --discover-timeout."
        ),
    )
    parser.add_argument(
        "--discover-only",
        action="store_true",
        dest="discover_only",
        help=(
            "With --discover, list the certificates Certificate Transparency "
            "knows for the domain(s) — expiry, issuer and hostnames, "
            "tab-separated, soonest expiry first — without connecting to any "
            "host, then exit. Wildcard certificates are included. Handy for a "
            "fast CT inventory or spotting a certificate from an unexpected CA."
        ),
    )
    parser.add_argument(
        "--expect-issuer",
        metavar="SUBSTRING",
        action="append",
        dest="expect_issuer",
        help=(
            "With --discover-only, flag any certificate whose issuer contains "
            "none of these substrings (case-insensitive) and exit with code 9, "
            "turning the CT inventory into a mis-issuance check. Repeat to "
            'allow several issuers, e.g. --expect-issuer "Let\'s Encrypt".'
        ),
    )
    parser.add_argument(
        "--discover-timeout",
        type=float,
        default=30.0,
        metavar="N",
        dest="discover_timeout",
        help=(
            "Timeout in seconds for the Certificate Transparency (crt.sh) query "
            "used by --discover (default: 30). Separate from --timeout, since "
            "the log search can be slower than a TLS handshake."
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
            "Fail (exit code 9) when an RSA or DSA public key is smaller than "
            "N bits (e.g. 2048). EC and EdDSA keys are not size-checked here; "
            "--fail-weak flags an EC key below 256 bit. Opt-in policy check."
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
        "--require-revocation-check",
        action="store_true",
        dest="require_revocation_check",
        help=(
            "Fail (exit code 9) unless OCSP or CRL returns a definitive GOOD "
            "revocation verdict. Host targets only; opt-in policy check."
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
        help=(
            "Save the inspected certificate as a PEM file at PATH. Needs a "
            "single target (host or --file)."
        ),
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
    parser.add_argument(
        "--state-file",
        metavar="PATH",
        dest="state_file",
        help=(
            "Persist each host target's status across runs at PATH (JSON) and "
            "compare against the previous run. Combine with --only-changed to "
            "show only the targets whose status changed; without it, the file "
            "is simply kept up to date for the next run. Host targets only; a "
            "target seen for the first time counts as changed, and one that "
            "cannot be reached keeps its last known status."
        ),
    )
    parser.add_argument(
        "--only-changed",
        action="store_true",
        dest="only_changed",
        help=(
            "Show only targets whose status differs from the previous "
            "--state-file run. Requires --state-file; affects the display "
            "only, not the exit code."
        ),
    )

    return parser
