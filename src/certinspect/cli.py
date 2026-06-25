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
from certinspect import __version__
from certinspect.fetch import get_server_cert
from certinspect.parser import (
    load_certificate,
    analyze,
    certificate_status,
    hostname_matches,
    to_pem,
)
from certinspect.formatter import format_human

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

    return parser


def _fetch_source(
    target: str | None, port: int, file: str | None, timeout: float
) -> tuple[bytes, dict | None]:
    """Return (raw certificate bytes, connection info) for one source.

    Connection info is None for local files (no live TLS handshake).
    """
    if file:
        with open(file, "rb") as f:
            return f.read(), None
    return get_server_cert(target, port, timeout)


def _inspect(
    target: str | None,
    *,
    port: int,
    file: str | None,
    days: int,
    export: str | None,
    timeout: float,
) -> tuple[dict, int]:
    """Inspect one source and return its (info, exit_code).

    The hostname match (and its exit code 5) only applies to host targets;
    with --file it is left as None.
    """
    der, conn = _fetch_source(target, port, file, timeout)
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
    return info, code


def _render(
    results: list[tuple[str | None, dict, int]],
    *,
    as_json: bool,
    days: int,
    quiet: bool,
) -> None:
    """Print the collected results as JSON (always a list) or human text.

    When ``quiet`` is set, only results with a non-zero exit code are shown.
    """
    if quiet:
        results = [r for r in results if r[2] != 0]

    if as_json:
        print(json.dumps([info for _, info, _ in results], indent=2, default=str))
        return

    blocks = []
    for target, info, _ in results:
        text = format_human(info, warn_days=days)
        blocks.append(f"=== {target} ===\n{text}" if target else text)
    if blocks:
        print("\n\n".join(blocks))


def main() -> None:
    """CLI entry point."""

    parser = build_parser()
    args = parser.parse_args()

    if not args.target and not args.file:
        parser.error("There is no target or no file to inspect.")

    # A single --file source has no host; otherwise iterate over the targets.
    targets: list[str | None] = [None] if args.file else list(args.target)

    results: list[tuple[str | None, dict, int]] = []
    codes: list[int] = []
    for target in targets:
        try:
            info, code = _inspect(
                target,
                port=args.port,
                file=args.file,
                days=args.days,
                export=args.export,
                timeout=args.timeout,
            )
        except (OSError, ssl.SSLError, ValueError) as err:
            label = f"{target}: " if target else ""
            print(f"error: {label}{err}", file=sys.stderr)
            codes.append(1)
            continue
        results.append((target, info, code))
        codes.append(code)

    _render(results, as_json=args.json, days=args.days, quiet=args.quiet)
    sys.exit(max(codes, default=0))


if __name__ == "__main__":
    main()
