"""Command-line entry point.

Wire together fetch -> parser -> formatter, reading the CLI arguments.

It fetches a certificate from one or more hosts (or reads a local file),
analyzes it, prints the result as human-readable text or JSON, and exits
with a status code reflecting the worst certificate state found.
"""

import argparse
import csv
import functools
import io
import json
import sys
import ssl
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, fields, replace
from pathlib import Path
from urllib.parse import urlsplit
from certinspect.args import build_parser
from certinspect.discover import (
    DiscoveredCert,
    discover_certificates,
    discover_hostnames,
)
from certinspect.fetch import (
    STARTTLS_PORTS,
    get_server_cert,
    retry_network,
    verify_chain,
    verify_chain_offline,
)
from certinspect.revocation import check_revocation
from certinspect.parser import (
    load_certificate,
    load_certificates,
    analyze,
    cab_forum_max_validity,
    certificate_status,
    chain_expiry_warnings,
    diagnose_chain,
    hostname_matches,
    missing_san_names,
    chain_summary,
    pin_matches,
    policy_violations,
    POLICY_PROFILES,
    to_pem,
)
from certinspect.exit_codes import EXIT_BY_STATUS, RUNTIME_ERROR, ExitCode, most_severe
from certinspect.models import CertificateInfo
from certinspect.completion import bash_completion_script, zsh_completion_script
from certinspect.config import DEFAULT_CONFIG_PATH, load_config
from certinspect.render import load_state, render, save_state


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
    connect_timeout: float | None = None
    read_timeout: float | None = None
    retries: int = 0
    verify: bool = True
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
    require_revocation_check: bool = False
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
        ``file`` is excluded from the mapping: ``args.file`` is a list of paths
        (one work item each) rather than the single value this field holds, so
        callers set it per-item with ``dataclasses.replace``.
        """
        return cls(
            **{f.name: getattr(args, f.name) for f in fields(cls) if f.name != "file"}
        )

    @property
    def effective_connect_timeout(self) -> float:
        """Connect timeout, defaulting to ``timeout`` when unset."""
        return (
            self.connect_timeout if self.connect_timeout is not None else self.timeout
        )

    @property
    def effective_read_timeout(self) -> float:
        """Read/handshake timeout, defaulting to ``timeout`` when unset."""
        return self.read_timeout if self.read_timeout is not None else self.timeout


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


def _connection_kwargs(opts: InspectOptions, *, include_ca: bool = False) -> dict:
    """Return the TLS connection keyword arguments shared by fetch and verify.

    ``include_ca`` adds the ``cafile``/``capath`` trust overrides that the
    verification handshake needs but the plain certificate fetch does not.
    """
    kwargs: dict = {"starttls": opts.starttls, "servername": opts.servername}
    if include_ca:
        kwargs["cafile"] = opts.cafile
        kwargs["capath"] = opts.capath
    if opts.client_cert:
        kwargs["client_cert"] = opts.client_cert
        kwargs["client_key"] = opts.client_key
    if opts.proxy:
        kwargs["proxy"] = opts.proxy
    if opts.no_proxy:
        kwargs["no_proxy"] = True
    return kwargs


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
    kwargs = _connection_kwargs(opts)
    timeouts = (opts.effective_connect_timeout, opts.effective_read_timeout)
    return retry_network(
        lambda: get_server_cert(target, port, timeouts, **kwargs),
        opts.retries,
    )


def _inspect(
    target: str | None,
    port: int,
    opts: InspectOptions,
) -> tuple[CertificateInfo, int]:
    """Inspect one source and return its (info, exit_code).

    The hostname match (and its exit code 5) only applies to host targets;
    with --file it is left as None. When ``servername`` is set it overrides
    both the SNI hostname and the name the hostname match is checked against.
    Chain verification (exit code 6) runs for host targets over a verified
    handshake and, with --file, offline against the certificates bundled in the
    file. A failed ``pin`` check yields exit code 7. When
    ``expect_san`` names are not all covered by the certificate's SAN the exit
    code is 8. The opt-in policy checks (``not_after_max``/``cab_forum``,
    ``min_key_size``, ``fail_weak``, ``require_sct``, ``require_must_staple``,
    ``min_tls_version``) yield exit code 9 when any is violated. When several
    checks fail, the most severe code wins (see ``exit_codes.most_severe``).
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
    codes = [EXIT_BY_STATUS[info["status"]]]
    if info["hostname_match"] is False:
        codes.append(ExitCode.HOSTNAME_MISMATCH)

    # A --file bundle may carry the whole chain; parse it once when it is needed.
    file_bundle: list | None = None
    if opts.file and (opts.verify or opts.chain):
        file_bundle = load_certificates(der)

    override, chain_certs = _check_chain(
        info, target, port, cert, conn, opts, file_bundle
    )
    codes.append(override)

    # The verified chain (when available) is the most accurate source for the
    # intermediates actually used; fall back to the chain presented by the
    # server. Either way the leaf is skipped by chain_expiry_warnings.
    if not chain_certs:
        if conn:
            chain_certs = conn.get("chain") or []
        elif file_bundle is not None:
            chain_certs = file_bundle

    chain_warnings = chain_expiry_warnings(chain_certs, opts.days)
    if chain_warnings:
        info["chain_warnings"] = chain_warnings

    if opts.chain:
        presented = (conn.get("chain") or [cert]) if conn else (file_bundle or [cert])
        info["chain"] = [chain_summary(c) for c in presented]

    codes += [
        _check_pin(info, opts),
        _check_expect_san(info, opts),
        _check_policy(info, opts),
    ]
    return info, most_severe(code for code in codes if code is not None)


def _check_chain(
    info: CertificateInfo,
    target: str | None,
    port: int,
    cert,
    conn: dict | None,
    opts: InspectOptions,
    file_bundle: list | None,
) -> tuple[ExitCode | None, list]:
    """Verify the chain (and, for hosts, revocation) and record the outcome.

    Sets the ``chain_trusted``/``chain_error``/``chain_diagnosis`` keys, and
    for host targets ``revocation_status``/``revocation_detail``, on ``info``.
    Returns the exit-code override (UNTRUSTED_OR_REVOKED when the chain is
    untrusted or the certificate is revoked, else None) and the chain to use
    for expiry warnings.
    """
    if opts.verify and opts.file:
        trusted, reason, verified = verify_chain_offline(
            file_bundle, cafile=opts.cafile, capath=opts.capath
        )
        info["chain_trusted"] = trusted
        info["chain_error"] = reason
        override = None
        if not trusted:
            override = ExitCode.UNTRUSTED_OR_REVOKED
            diagnosis = diagnose_chain(file_bundle)
            if diagnosis:
                info["chain_diagnosis"] = diagnosis
        return override, verified or file_bundle
    if opts.verify and target:
        verify_kwargs = _connection_kwargs(opts, include_ca=True)
        timeouts = (opts.effective_connect_timeout, opts.effective_read_timeout)
        trusted, reason, verified = retry_network(
            lambda: verify_chain(target, port, timeouts, **verify_kwargs),
            opts.retries,
        )
        info["chain_trusted"] = trusted
        info["chain_error"] = reason
        override = None
        if not trusted:
            override = ExitCode.UNTRUSTED_OR_REVOKED
            presented = conn.get("chain") if conn else None
            if presented:
                diagnosis = diagnose_chain(presented)
                if diagnosis:
                    info["chain_diagnosis"] = diagnosis

        # Prefer the issuer from the verified chain; fall back to AIA download.
        issuer = verified[1] if len(verified) > 1 else None
        revocation, detail = check_revocation(cert, opts.timeout, issuer=issuer)
        info["revocation_status"] = revocation
        info["revocation_detail"] = detail
        if revocation == "REVOKED":
            override = ExitCode.UNTRUSTED_OR_REVOKED
        return override, verified
    return None, []


def _check_pin(info: CertificateInfo, opts: InspectOptions) -> ExitCode | None:
    """Record the fingerprint-pin result; return PIN_MISMATCH when it fails."""
    if not opts.pin:
        return None
    info["pin_match"] = pin_matches(info, opts.pin)
    return None if info["pin_match"] else ExitCode.PIN_MISMATCH


def _check_expect_san(info: CertificateInfo, opts: InspectOptions) -> ExitCode | None:
    """Record the missing expected SAN names; return SAN_MISMATCH when any."""
    if not opts.expect_san:
        return None
    missing = missing_san_names(info, opts.expect_san)
    info["expected_san_missing"] = missing
    return ExitCode.SAN_MISMATCH if missing else None


def _check_policy(info: CertificateInfo, opts: InspectOptions) -> ExitCode | None:
    """Record the opt-in policy violations; return POLICY when any applies."""
    if not (
        opts.not_after_max is not None
        or opts.cab_forum
        or opts.min_key_size is not None
        or opts.fail_weak
        or opts.require_sct
        or opts.require_must_staple
        or opts.require_revocation_check
        or opts.min_tls_version is not None
    ):
        return None
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
    if opts.require_revocation_check:
        violation = _revocation_policy_violation(info)
        if violation is not None:
            violations.append(violation)
    info["policy_violations"] = violations
    return ExitCode.POLICY if violations else None


def _revocation_policy_violation(info: CertificateInfo) -> str | None:
    """Return a policy violation when revocation was not proven GOOD."""
    status = info.get("revocation_status")
    if status == "GOOD":
        return None
    detail = info.get("revocation_detail")
    if detail:
        return f"revocation check did not return GOOD ({status}: {detail})"
    return f"revocation check did not return GOOD ({status or 'not run'})"


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


def _discover_all(domains: list[str], timeout: float, workers: int, fetch) -> list:
    """Run ``fetch(domain, timeout)`` for every domain, in parallel when asked.

    Returns the ``(domain, result, error)`` outcomes in ``domains`` order
    regardless of concurrency, so callers can report them deterministically.
    """
    call = functools.partial(_discover_one, timeout=timeout, fetch=fetch)
    workers = max(1, workers)
    if workers > 1 and len(domains) > 1:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            return list(pool.map(call, domains))
    return [call(domain) for domain in domains]


def _issuer_is_expected(issuer: str, expected: list[str]) -> bool:
    """Return True when the issuer matches at least one expected substring.

    Matching is a case-insensitive substring test, so a short brand fragment
    like "Let's Encrypt" recognizes every CA name that contains it.
    """
    lowered = issuer.lower()
    return any(token.lower() in lowered for token in expected)


def _run_discover_only(args: argparse.Namespace) -> None:
    """List the CT inventory for the --discover domains and exit.

    Prints one certificate per line (expiry, issuer, hostnames), soonest expiry
    first, so the whole Certificate Transparency picture — dead hosts and
    unexpected issuers included — is visible without a live handshake. With
    --expect-issuer, certificates from any other CA are flagged and the exit
    code becomes 9; with --json the inventory is emitted as a JSON array.
    """
    expected = args.expect_issuer or []
    rows: list[tuple[str, DiscoveredCert, bool]] = []
    outcomes = _discover_all(
        args.discover, args.discover_timeout, args.concurrency, discover_certificates
    )
    for domain, certs, err in outcomes:
        if err is not None:
            print(f"error: discovery for {domain}: {err}", file=sys.stderr)
            sys.exit(1)
        if certs:
            print(
                f"discovered {len(certs)} certificate(s) for {domain}",
                file=sys.stderr,
            )
        else:
            print(f"warning: no certificates found for {domain}", file=sys.stderr)
        for cert in certs:
            unexpected = bool(expected) and not _issuer_is_expected(
                cert.issuer, expected
            )
            rows.append((domain, cert, unexpected))

    unexpected_count = sum(1 for _, _, unexpected in rows if unexpected)

    if args.json:
        payload = []
        for domain, cert, unexpected in rows:
            record = {
                "domain": domain,
                "hostnames": list(cert.hostnames),
                "issuer": cert.issuer,
                "not_before": cert.not_before,
                "not_after": cert.not_after,
            }
            if expected:
                record["unexpected_issuer"] = unexpected
            payload.append(record)
        print(json.dumps(payload, indent=2, default=str, ensure_ascii=False))
    elif args.csv:
        buffer = io.StringIO()
        writer = csv.writer(buffer, delimiter=args.csv_delimiter, lineterminator="\n")
        header = ["domain", "hostnames", "issuer", "not_before", "not_after"]
        if expected:
            header.append("unexpected_issuer")
        writer.writerow(header)
        for domain, cert, unexpected in rows:
            record = [
                domain,
                " ".join(cert.hostnames),
                cert.issuer,
                cert.not_before,
                cert.not_after,
            ]
            if expected:
                record.append("yes" if unexpected else "no")
            writer.writerow(record)
        print(buffer.getvalue(), end="")
    else:
        for _, cert, unexpected in rows:
            line = f"{cert.not_after}\t{cert.issuer}\t{', '.join(cert.hostnames)}"
            print(f"{line}\tUNEXPECTED" if unexpected else line)

    if expected and unexpected_count:
        print(
            f"warning: {unexpected_count} certificate(s) from an unexpected issuer",
            file=sys.stderr,
        )

    if args.exit_zero:
        sys.exit(0)
    sys.exit(9 if unexpected_count else 0)


def _validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Reject flag combinations argparse cannot express, via ``parser.error``.

    Covers the value constraints (a single-character CSV delimiter, a critical
    window no wider than the warning one) and the applicability rules
    (flags that only make sense for host targets, for --file, or with
    verification enabled). Each violation aborts with argparse's usage exit
    code 2.
    """
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
    if args.discover and args.file:
        parser.error("--discover applies to host targets, not --file.")
    if args.discover_only and not args.discover:
        parser.error("--discover-only requires --discover.")
    if args.expect_issuer and not args.discover_only:
        parser.error("--expect-issuer requires --discover-only.")
    if args.only_changed and not args.state_file:
        parser.error("--only-changed requires --state-file.")
    if args.state_file and args.file:
        parser.error("--state-file applies to host targets, not --file.")


def main() -> None:
    """CLI entry point."""
    parser = build_parser()

    # --config must be resolved before the real parse: its values become the
    # argparse defaults, which an explicit command-line flag still overrides.
    config_pre_parser = argparse.ArgumentParser(add_help=False)
    config_pre_parser.add_argument("--config")
    pre_args, _ = config_pre_parser.parse_known_args()
    if pre_args.config:
        if not Path(pre_args.config).is_file():
            parser.error(f"--config file not found: {pre_args.config}")
        config_path: Path | None = Path(pre_args.config)
    elif DEFAULT_CONFIG_PATH.is_file():
        config_path = DEFAULT_CONFIG_PATH
    else:
        config_path = None
    if config_path is not None:
        try:
            parser.set_defaults(**load_config(str(config_path), parser))
        except ValueError as err:
            parser.error(str(err))

    args = parser.parse_args()

    if args.print_completion:
        script = (
            bash_completion_script(parser)
            if args.print_completion == "bash"
            else zsh_completion_script(parser)
        )
        print(script, end="")
        sys.exit(0)

    _apply_profile(args)

    _validate_args(args, parser)

    if args.discover_only:
        _run_discover_only(args)

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
        outcomes = _discover_all(
            args.discover, args.discover_timeout, args.concurrency, discover_hostnames
        )
        for domain, found, err in outcomes:
            if err is not None:
                print(f"error: discovery for {domain}: {err}", file=sys.stderr)
                sys.exit(1)
            if found:
                print(
                    f"discovered {len(found)} hostname(s) for {domain}",
                    file=sys.stderr,
                )
            else:
                print(f"warning: no certificates found for {domain}", file=sys.stderr)
            discovered_targets.extend(found)

    host_targets = [*args.target, *extra_targets, *discovered_targets]
    file_targets = args.file or []

    if file_targets and host_targets:
        parser.error("--file cannot be combined with host targets.")
    if not host_targets and not file_targets:
        parser.error("There is no target or no file to inspect.")
    if file_targets.count("-") > 1:
        parser.error("--file '-' (standard input) may be given at most once.")

    # With STARTTLS, fall back to the protocol's standard port unless the user
    # passed --port explicitly (i.e. it differs from the 443 default).
    default_port = args.port
    if args.starttls and default_port == 443:
        default_port = STARTTLS_PORTS[args.starttls]

    opts = InspectOptions.from_args(args)

    # A single --file source keeps the old unlabelled output; with several
    # files (or several hosts) each result is labelled to tell them apart.
    single_file = len(file_targets) == 1
    work_items: list[tuple[bool, str]] = [(True, path) for path in file_targets]
    work_items += [(False, raw) for raw in host_targets]

    def _run(item: tuple[bool, str]) -> tuple[str, tuple | None, str | None]:
        """Inspect one work item, returning (name, payload, error).

        ``item`` is ``(is_file, raw)``: a file path or a host target string.
        ``name`` labels the item (``host[:port]`` for a host, the path for a
        file). ``payload`` is ``(label, info, code)`` on success and None on
        failure, in which case ``error`` carries the message. Runs in worker
        threads, so it must not perform any I/O on shared streams.
        """
        is_file, raw = item
        name = raw
        try:
            if is_file:
                file_opts = replace(opts, file=raw)
                info, code = _inspect(None, default_port, file_opts)
                return name, (None if single_file else raw, info, code), None
            target, port = _split_target(raw, default_port)
            name = _target_label(target, port, default_port)
            info, code = _inspect(target, port, opts)
        except (OSError, ssl.SSLError, ValueError) as err:
            return name, None, str(err)
        return name, (name, info, code), None

    # Inspect in parallel when asked; ThreadPoolExecutor.map preserves order.
    workers = max(1, args.concurrency)
    if workers > 1 and len(work_items) > 1:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            outcomes = list(pool.map(_run, work_items))
    else:
        outcomes = [_run(item) for item in work_items]

    results: list[tuple[str | None, dict, int]] = []
    errors: list[tuple[str | None, str]] = []
    codes: list[int] = []
    for name, payload, err in outcomes:
        if err is not None:
            if not args.exporter:
                label = f"{name}: " if name else ""
                print(f"error: {label}{err}", file=sys.stderr)
            errors.append((name, err))
            codes.append(RUNTIME_ERROR)
            continue
        results.append(payload)
        codes.append(payload[2])

    changed_targets: set[str] | None = None
    if args.state_file:
        previous_state = load_state(args.state_file)
        current_state = {t: info["status"] for t, info, _ in results if t is not None}
        changed_targets = {
            t for t, status in current_state.items() if previous_state.get(t) != status
        }
        save_state(args.state_file, current_state)

    override = render(
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
        schema=args.schema,
        errors=errors,
        changed_targets=changed_targets if args.only_changed else None,
    )
    if args.exit_zero:
        sys.exit(0)
    sys.exit(override if override is not None else most_severe(codes))


if __name__ == "__main__":
    main()
