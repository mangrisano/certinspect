"""Command-line entry point.

Wire together fetch -> parser -> formatter, reading the CLI arguments.

It fetches a certificate from one or more hosts (or reads a local file),
analyzes it, prints the result as human-readable text or JSON, and exits
with a status code reflecting the worst certificate state found.
"""

import argparse
import functools
import math
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlsplit

from certinspect import httpfetch
from certinspect.args import build_parser
from certinspect.completion import bash_completion_script, zsh_completion_script
from certinspect.config import DEFAULT_CONFIG_PATH, exclusive_groups, load_config
from certinspect.discover import (
    DiscoveredCert,
    discover_certificates,
    discover_hostnames,
)
from certinspect.exit_codes import RUNTIME_ERROR, ExitCode, most_severe
from certinspect.fetch import (
    STARTTLS_PORTS,
    get_server_cert,
    resolve_host_ips,
    trust_anchors,
    verify_chain,
    verify_chain_offline,
)
from certinspect.formatter import format_ct_inventory
from certinspect.inspector import (
    InspectOptions,
    default_backend_for,
    inspect_target,
)
from certinspect.models import CertificateInfo, InspectionResult
from certinspect.parser import POLICY_PROFILES
from certinspect.render import OutputOptions, render
from certinspect.revocation import check_revocation, complete_chain
from certinspect.state import update_state


def _split_target(raw: str, default_port: int) -> tuple[str, int]:
    """Normalize a target into ``(host, port)``.

    Accepts a bare hostname, a ``host:port`` pair, or a full URL (the scheme
    and any path are ignored). An explicit port in the target overrides
    ``default_port``.
    """
    spec = raw if "://" in raw else f"//{raw}"
    parts = urlsplit(spec)
    return parts.hostname or raw, parts.port or default_port


def _target_label(host: str, port: int, default_port: int) -> str:
    """Name a host result: the bare host on the default port, else ``host:port``.

    Keeps the common case unchanged while telling apart several services on the
    same host (output, --state-file keys, Prometheus labels).
    """
    if port == default_port:
        return host
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def _inspect(
    target: str | None,
    port: int,
    opts: InspectOptions,
) -> tuple[CertificateInfo, int]:
    """Inspect one source using the CLI's current backend bindings."""
    backend = default_backend_for(
        get_server_cert_fn=get_server_cert,
        verify_chain_fn=verify_chain,
        verify_chain_offline_fn=verify_chain_offline,
        trust_anchors_fn=trust_anchors,
        check_revocation_fn=check_revocation,
        complete_chain_fn=complete_chain,
    )
    return inspect_target(target, port, opts, backend=backend)


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


def _discover_one(
    domain: str, *, timeout: float, fetch
) -> tuple[str, list | None, str | None]:
    """Run one ``fetch(domain, timeout)`` call, returning (domain, result, error)."""
    try:
        return domain, fetch(domain, timeout), None
    except (OSError, ValueError) as err:
        return domain, None, str(err)


def _map(call, items: list, workers: int) -> list:
    """Return ``[call(item) for item in items]``, in threads when ``workers`` > 1.

    ThreadPoolExecutor.map keeps the input order, so the output is
    deterministic regardless of concurrency.
    """
    workers = max(1, workers)
    if workers > 1 and len(items) > 1:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            return list(pool.map(call, items))
    return [call(item) for item in items]


def _discover(
    domains: list[str], timeout: float, workers: int, fetch, noun: str
) -> list[tuple[str, list]]:
    """Run ``fetch(domain, timeout)`` for every domain and report it on stderr.

    ``noun`` names what ``fetch`` returns ("hostname", "certificate") in the
    per-domain message. The first failed domain aborts with exit code 1, like
    an unreadable --input. Returns ``(domain, result)`` pairs in input order.
    """
    call = functools.partial(_discover_one, timeout=timeout, fetch=fetch)
    found = []
    for domain, result, err in _map(call, domains, workers):
        if err is not None:
            print(f"error: discovery for {domain}: {err}", file=sys.stderr)
            sys.exit(1)
        if result:
            print(f"discovered {len(result)} {noun}(s) for {domain}", file=sys.stderr)
        else:
            print(f"warning: no certificates found for {domain}", file=sys.stderr)
        found.append((domain, result))
    return found


def _issuer_is_expected(issuer: str, expected: list[str]) -> bool:
    """Return True when the issuer matches at least one expected substring.

    Matching is a case-insensitive substring test, so a short brand fragment
    like "Let's Encrypt" recognizes every CA name that contains it.
    """
    lowered = issuer.lower()
    return any(token.lower() in lowered for token in expected)


def _run_discover_only(args: argparse.Namespace) -> ExitCode:
    """Print the CT inventory for the --discover domains, return the exit code.

    Prints one certificate per line (expiry, issuer, hostnames), soonest expiry
    first, so the whole Certificate Transparency picture — dead hosts and
    unexpected issuers included — is visible without a live handshake. With
    --expect-issuer, certificates from any other CA are flagged and the result
    is POLICY; with --json/--csv the inventory uses that format.
    """
    expected = args.expect_issuer or []
    rows: list[tuple[str, DiscoveredCert, bool]] = []
    inventory = _discover(
        args.discover,
        args.discover_timeout,
        args.concurrency,
        discover_certificates,
        "certificate",
    )
    for domain, certs in inventory:
        for cert in certs:
            unexpected = bool(expected) and not _issuer_is_expected(
                cert.issuer, expected
            )
            rows.append((domain, cert, unexpected))

    unexpected_count = sum(1 for _, _, unexpected in rows if unexpected)

    text = format_ct_inventory(
        rows,
        as_json=args.json,
        as_csv=args.csv,
        delimiter=args.csv_delimiter,
        flag_issuer=bool(expected),
    )
    print(text, end="")

    if unexpected_count:
        print(
            f"warning: {unexpected_count} certificate(s) from an unexpected issuer",
            file=sys.stderr,
        )
        return ExitCode.POLICY
    return ExitCode.OK


def _validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Reject flag combinations argparse cannot express, via ``parser.error``.

    Covers the value constraints (a single-character CSV delimiter, a critical
    window no wider than the warning one) and the applicability rules
    (flags that only make sense for host targets, for --file, or with
    verification enabled). Each violation aborts with argparse's usage exit
    code 2.
    """
    if not (1 <= args.port <= 65535):
        parser.error("--port must be between 1 and 65535.")
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be a finite number greater than 0.")
    if args.connect_timeout is not None and (
        not math.isfinite(args.connect_timeout) or args.connect_timeout <= 0
    ):
        parser.error("--connect-timeout must be a finite number greater than 0.")
    if args.read_timeout is not None and (
        not math.isfinite(args.read_timeout) or args.read_timeout <= 0
    ):
        parser.error("--read-timeout must be a finite number greater than 0.")
    if not math.isfinite(args.discover_timeout) or args.discover_timeout <= 0:
        parser.error("--discover-timeout must be a finite number greater than 0.")
    if args.retries < 0:
        parser.error("--retries must be 0 or greater.")
    if args.concurrency < 1:
        parser.error("--concurrency must be at least 1.")
    if len(args.csv_delimiter) != 1:
        parser.error("--csv-delimiter must be a single character.")
    if args.critical_days is not None and args.critical_days > args.days:
        parser.error("--critical-days must be less than or equal to --days.")
    if (args.cafile or args.capath) and not args.verify:
        parser.error("--cafile/--capath cannot be combined with --no-verify.")
    if args.servername and args.file:
        parser.error("--servername applies to host targets, not --file.")
    if args.min_tls_version and args.file:
        parser.error("--min-tls-version applies to host targets, not --file.")
    if args.require_revocation_check and args.file:
        parser.error("--require-revocation-check applies to host targets, not --file.")
    if args.require_revocation_check and not args.verify:
        parser.error("--require-revocation-check cannot be combined with --no-verify.")
    if args.client_key and not args.client_cert:
        parser.error("--client-key requires --client-cert.")
    if args.proxy and args.no_proxy:
        parser.error("--proxy and --no-proxy are mutually exclusive.")
    if (args.client_cert or args.proxy or args.no_proxy) and args.file:
        parser.error(
            "--client-cert/--proxy/--no-proxy apply to host targets, not --file."
        )
    if args.export_chain and not args.file:
        parser.error("--export-chain applies to --file, not host targets.")
    if args.include_root and not args.export_chain:
        parser.error("--include-root requires --export-chain.")
    if args.discover and args.file:
        parser.error("--discover applies to host targets, not --file.")
    if args.discover_only and not args.discover:
        parser.error("--discover-only requires --discover.")
    if args.expect_issuer and not args.discover_only:
        parser.error("--expect-issuer requires --discover-only.")
    if args.only_changed and not args.state_file:
        parser.error("--only-changed requires --state-file.")
    if (args.ipv4 or args.ipv6 or args.all_ips) and args.file:
        parser.error("-4/-6/--all-ips apply to host targets, not --file.")
    if args.all_ips and args.export:
        parser.error("--export cannot be combined with --all-ips.")
    if args.state_file and args.file:
        parser.error("--state-file applies to host targets, not --file.")


def _cli_explicit_dests(parser: argparse.ArgumentParser, argv: list[str]) -> set[str]:
    """Return the argparse destinations explicitly passed on ``argv``."""
    flag_to_dest: dict[str, str] = {}
    for action in parser._actions:
        for opt in action.option_strings:
            flag_to_dest[opt] = action.dest
    explicit: set[str] = set()
    for token in argv:
        if token == "--":
            break
        flag = token.split("=", 1)[0]
        if flag in flag_to_dest:
            explicit.add(flag_to_dest[flag])
    return explicit


def _parse_args(parser: argparse.ArgumentParser) -> argparse.Namespace:
    """Parse the command line on top of the defaults from the config file."""
    # --config must be resolved before the real parse: its values become the
    # argparse defaults, which an explicit command-line flag still overrides.
    argv = sys.argv[1:]
    config_pre_parser = argparse.ArgumentParser(add_help=False)
    config_pre_parser.add_argument("--config")
    pre_args, _ = config_pre_parser.parse_known_args(argv)
    if pre_args.config is not None:
        if not pre_args.config or not Path(pre_args.config).is_file():
            parser.error(f"--config file not found: {pre_args.config}")
        config_path: Path | None = Path(pre_args.config)
    elif DEFAULT_CONFIG_PATH.is_file():
        config_path = DEFAULT_CONFIG_PATH
    else:
        config_path = None
    if config_path is not None:
        try:
            config_data = load_config(str(config_path), parser)
        except ValueError as err:
            parser.error(str(err))
        explicit = _cli_explicit_dests(parser, argv)
        for group in exclusive_groups(parser):
            if any(dest in explicit for dest in group):
                for dest in group:
                    if dest not in explicit:
                        config_data.pop(dest, None)
        parser.set_defaults(**config_data)
    return parser.parse_args(argv)


def _completion_script(parser: argparse.ArgumentParser, shell: str) -> str:
    """Return the completion script for ``shell`` ('bash' or 'zsh')."""
    if shell == "bash":
        return bash_completion_script(parser)
    return zsh_completion_script(parser)


def _collect_targets(
    args: argparse.Namespace, parser: argparse.ArgumentParser
) -> tuple[list[str], list[str]]:
    """Return ``(host_targets, file_targets)``, --input and --discover included.

    Rejects an empty or inconsistent target set via ``parser.error``; an
    unreadable --input file aborts with exit code 1.
    """
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
    discovered_targets: list[str] = []
    if args.discover:
        for _, found in _discover(
            args.discover,
            args.discover_timeout,
            args.concurrency,
            discover_hostnames,
            "hostname",
        ):
            discovered_targets.extend(found)

    host_targets = [*args.target, *extra_targets, *discovered_targets]
    file_targets = args.file or []

    if file_targets and host_targets:
        parser.error("--file cannot be combined with host targets.")
    if not host_targets and not file_targets:
        parser.error("There is no target or no file to inspect.")
    if file_targets.count("-") > 1:
        parser.error("--file '-' (standard input) may be given at most once.")
    if args.export and len(host_targets) + len(file_targets) > 1:
        parser.error("--export saves a single certificate; give one target.")
    if args.export_chain and len(file_targets) > 1:
        parser.error("--export-chain saves a single chain; give one --file.")
    return host_targets, file_targets


def _default_port(args: argparse.Namespace) -> int:
    """Return --port, or the STARTTLS protocol's port when --port was not given."""
    if args.starttls and args.port == 443:
        return STARTTLS_PORTS[args.starttls]
    return args.port


def _expand_host_items(
    host_targets: list[str],
    default_port: int,
    opts: InspectOptions,
    all_ips: bool,
) -> tuple[list[tuple[bool, str, int, str, InspectOptions]], list[tuple[str, str]]]:
    """Build host work items, expanding each host to all resolved IPs when ``all_ips``."""
    items: list[tuple[bool, str, int, str, InspectOptions]] = []
    resolve_errors: list[tuple[str, str]] = []
    family = opts.connection.ip_family
    for raw in host_targets:
        target, port = _split_target(raw, default_port)
        base_label = _target_label(target, port, default_port)
        if not all_ips:
            items.append((False, target, port, base_label, opts))
            continue
        try:
            ips = resolve_host_ips(target, port, family=family)
        except OSError as err:
            resolve_errors.append((base_label, str(err)))
            continue
        sni = opts.servername or target
        ip_opts = replace(opts, servername=sni)
        for ip in ips:
            items.append((False, ip, port, f"{base_label} [{ip}]", ip_opts))
    return items, resolve_errors


def _inspect_all(
    args: argparse.Namespace, host_targets: list[str], file_targets: list[str]
) -> tuple[list[InspectionResult], list[tuple[str | None, str]], list[int]]:
    """Inspect every target, returning ``(results, errors, codes)``.

    Failures are reported on stderr (unless an exporter is selected) and
    counted as RUNTIME_ERROR; ``codes`` holds one exit code per target.
    """
    default_port = _default_port(args)
    opts = InspectOptions.from_args(args)

    # A single --file source keeps the old unlabelled output; with several
    # files (or several hosts) each result is labelled to tell them apart.
    single_file = len(file_targets) == 1
    work_items: list[tuple[bool, str, int, str, InspectOptions]] = [
        (True, path, default_port, path, replace(opts, file=path))
        for path in file_targets
    ]
    host_items, resolve_errors = _expand_host_items(
        host_targets, default_port, opts, args.all_ips
    )
    work_items.extend(host_items)

    def _run(
        item: tuple[bool, str, int, str, InspectOptions],
    ) -> tuple[str, InspectionResult | None, str | None]:
        """Inspect one work item, returning (name, result, error)."""
        is_file, target, port, name, item_opts = item
        try:
            if is_file:
                info, code = _inspect(None, port, item_opts)
                label = None if single_file else name
                return name, InspectionResult(label, info, code), None
            info, code = _inspect(target, port, item_opts)
        except (OSError, ssl.SSLError, ValueError, OverflowError) as err:
            return name, None, str(err)
        return name, InspectionResult(name, info, code), None

    results: list[InspectionResult] = []
    errors: list[tuple[str | None, str]] = []
    codes: list[int] = []
    for name, err in resolve_errors:
        if not args.exporter:
            print(f"error: {name}: {err}", file=sys.stderr)
        errors.append((name, err))
        codes.append(RUNTIME_ERROR)
    for name, result, err in _map(_run, work_items, args.concurrency):
        if err is not None:
            if not args.exporter:
                label = f"{name}: " if name else ""
                print(f"error: {label}{err}", file=sys.stderr)
            errors.append((name, err))
            codes.append(RUNTIME_ERROR)
            continue
        results.append(result)
        codes.append(result.code)
    return results, errors, codes


def main() -> None:
    """CLI entry point."""
    parser = build_parser()
    args = _parse_args(parser)

    if args.print_completion:
        print(_completion_script(parser, args.print_completion), end="")
        sys.exit(0)

    _apply_profile(args)
    _validate_args(args, parser)
    httpfetch.use_proxy(args.proxy, args.no_proxy)

    if args.discover_only:
        code = _run_discover_only(args)
        sys.exit(0 if args.exit_zero else code)

    host_targets, file_targets = _collect_targets(args, parser)
    results, errors, codes = _inspect_all(args, host_targets, file_targets)

    changed_targets = None
    if args.state_file:
        changed_targets = update_state(args.state_file, results, errors)

    override = render(
        results,
        errors,
        OutputOptions.from_args(args),
        changed_targets if args.only_changed else None,
    )
    if args.exit_zero:
        sys.exit(0)
    sys.exit(override if override is not None else most_severe(codes))


if __name__ == "__main__":
    main()
