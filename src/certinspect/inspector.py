"""Certificate inspection pipeline and cohesive option models.

Separates the reusable inspection workflow from the CLI orchestration in
``cli.py`` (SRP), groups related configuration knobs into focused option
views (ISP), and accepts injectable network/revocation callables (DIP).
"""

import argparse
import socket
import sys
from collections.abc import Callable
from dataclasses import dataclass, fields
from typing import Any

from certinspect import fetch as _fetch_mod
from certinspect.exit_codes import (
    EXIT_BY_STATUS,
    ExitCode,
    RevocationStatus,
    most_severe,
)
from certinspect.fetch import (
    fetch_verified_cert,
    get_server_cert,
    retry_network,
    trust_anchors,
    verify_chain,
    verify_chain_offline,
)
from certinspect.models import CertificateInfo, ConnectionInfo
from certinspect.parser import (
    analyze,
    cab_forum_max_validity,
    certificate_status,
    chain_expiry_warnings,
    chain_summary,
    common_name,
    diagnose_chain,
    hostname_matches,
    load_certificate,
    load_certificates,
    missing_san_names,
    pin_matches,
    policy_violations,
    to_pem,
)
from certinspect.revocation import check_revocation, complete_chain


@dataclass(frozen=True)
class ConnectionOptions:
    """Network, TLS, proxy, and mTLS settings for host inspections."""

    timeout: float = 5.0
    connect_timeout: float | None = None
    read_timeout: float | None = None
    retries: int = 0
    starttls: str | None = None
    cafile: str | None = None
    capath: str | None = None
    servername: str | None = None
    client_cert: str | None = None
    client_key: str | None = None
    proxy: str | None = None
    no_proxy: bool = False
    ipv4: bool = False
    ipv6: bool = False

    @property
    def ip_family(self) -> int:
        if self.ipv4:
            return socket.AF_INET
        if self.ipv6:
            return socket.AF_INET6
        return socket.AF_UNSPEC

    @property
    def effective_connect_timeout(self) -> float:
        return (
            self.connect_timeout if self.connect_timeout is not None else self.timeout
        )

    @property
    def effective_read_timeout(self) -> float:
        return self.read_timeout if self.read_timeout is not None else self.timeout

    @property
    def timeouts(self) -> tuple[float, float]:
        return (self.effective_connect_timeout, self.effective_read_timeout)

    def to_kwargs(self, *, include_ca: bool = False) -> dict[str, Any]:
        """Return TLS connection keyword arguments for fetch/verify helpers."""
        kwargs: dict[str, Any] = {
            "starttls": self.starttls,
            "servername": self.servername,
        }
        if include_ca:
            kwargs["cafile"] = self.cafile
            kwargs["capath"] = self.capath
        if self.client_cert:
            kwargs["client_cert"] = self.client_cert
            kwargs["client_key"] = self.client_key
        if self.proxy:
            kwargs["proxy"] = self.proxy
        if self.no_proxy:
            kwargs["no_proxy"] = True
        if self.ipv4:
            kwargs["family"] = socket.AF_INET
        elif self.ipv6:
            kwargs["family"] = socket.AF_INET6
        return kwargs


@dataclass(frozen=True)
class PolicyOptions:
    """Opt-in policy checks (exit code 9)."""

    not_after_max: int | None = None
    cab_forum: bool = False
    min_key_size: int | None = None
    fail_weak: bool = False
    require_sct: bool = False
    require_must_staple: bool = False
    require_revocation_check: bool = False
    min_tls_version: str | None = None

    @property
    def requested(self) -> bool:
        """True when at least one opt-in policy check is enabled."""
        return any(
            (value := getattr(self, f.name)) is not None and value is not False
            for f in fields(self)
        )


@dataclass(frozen=True)
class ExportOptions:
    """PEM export settings for single-target runs."""

    export: str | None = None
    export_chain: str | None = None
    include_root: bool = False


@dataclass(frozen=True)
class InspectOptions:
    """Per-run inspection options shared by every target in a batch.

    Keeps flat field names matching argparse destinations while exposing
    cohesive sub-views (``connection``, ``policy``, ``export_opts``) so
    individual pipeline steps depend only on the slice they need.
    """

    file: str | None = None
    days: int = 30
    critical_days: int | None = None
    export: str | None = None
    export_chain: str | None = None
    include_root: bool = False
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
    ipv4: bool = False
    ipv6: bool = False

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "InspectOptions":
        """Build the options from parsed CLI arguments."""
        return cls(
            **{f.name: getattr(args, f.name) for f in fields(cls) if f.name != "file"}
        )

    @property
    def connection(self) -> ConnectionOptions:
        return ConnectionOptions(
            timeout=self.timeout,
            connect_timeout=self.connect_timeout,
            read_timeout=self.read_timeout,
            retries=self.retries,
            starttls=self.starttls,
            cafile=self.cafile,
            capath=self.capath,
            servername=self.servername,
            client_cert=self.client_cert,
            client_key=self.client_key,
            proxy=self.proxy,
            no_proxy=self.no_proxy,
            ipv4=self.ipv4,
            ipv6=self.ipv6,
        )

    @property
    def policy(self) -> PolicyOptions:
        return PolicyOptions(
            not_after_max=self.not_after_max,
            cab_forum=self.cab_forum,
            min_key_size=self.min_key_size,
            fail_weak=self.fail_weak,
            require_sct=self.require_sct,
            require_must_staple=self.require_must_staple,
            require_revocation_check=self.require_revocation_check,
            min_tls_version=self.min_tls_version,
        )

    @property
    def export_opts(self) -> ExportOptions:
        return ExportOptions(
            export=self.export,
            export_chain=self.export_chain,
            include_root=self.include_root,
        )

    @property
    def effective_connect_timeout(self) -> float:
        return self.connection.effective_connect_timeout

    @property
    def effective_read_timeout(self) -> float:
        return self.connection.effective_read_timeout

    @property
    def policy_requested(self) -> bool:
        return self.policy.requested


@dataclass(frozen=True)
class InspectionBackend:
    """Injectable I/O operations used by ``inspect_target`` (DIP)."""

    get_server_cert: Callable[..., tuple[bytes, ConnectionInfo]] = get_server_cert
    verify_chain: Callable[..., tuple[bool, str | None, list]] = verify_chain
    fetch_verified_cert: (
        Callable[..., tuple[bytes, ConnectionInfo, bool, str | None, list]] | None
    ) = fetch_verified_cert
    verify_chain_offline: Callable[..., tuple[bool, str | None, list]] = (
        verify_chain_offline
    )
    trust_anchors: Callable[..., list] = trust_anchors
    check_revocation: Callable[..., tuple[RevocationStatus, str | None]] = (
        check_revocation
    )
    complete_chain: Callable[..., tuple[list, bool]] = complete_chain


_DEFAULT_BACKEND = InspectionBackend()


def _read_local_source(path: str) -> bytes:
    if path == "-":
        return sys.stdin.buffer.read()
    with open(path, "rb") as f:
        return f.read()


def _fetch_source(
    target: str | None,
    port: int,
    opts: InspectOptions,
    backend: InspectionBackend,
) -> tuple[bytes, ConnectionInfo | None, tuple[bool, str | None, list] | None]:
    """Fetch certificate bytes and optional inline verification outcome.

    For host targets with ``verify=True`` and ``backend.fetch_verified_cert``
    available, uses a single verified TLS handshake (falling back to an
    unverified handshake only on verification failure).
    """
    if opts.file:
        return _read_local_source(opts.file), None, None

    conn_opts = opts.connection
    host = target
    assert host is not None, "a source is either a file or a host"

    fetch_verified = backend.fetch_verified_cert
    if opts.verify and fetch_verified is not None:
        kwargs = conn_opts.to_kwargs(include_ca=True)
        der, conn, trusted, reason, verified = retry_network(
            lambda: fetch_verified(host, port, conn_opts.timeouts, **kwargs),
            conn_opts.retries,
        )
        return der, conn, (trusted, reason, verified)

    kwargs = conn_opts.to_kwargs()
    der, conn = retry_network(
        lambda: backend.get_server_cert(host, port, conn_opts.timeouts, **kwargs),
        conn_opts.retries,
    )
    return der, conn, None


def _export_chain(
    bundle: list,
    export_opts: ExportOptions,
    conn_opts: ConnectionOptions,
    backend: InspectionBackend,
) -> list:
    """Write the completed chain of ``bundle`` to ``export_opts.export_chain``."""
    assert export_opts.export_chain is not None
    chain, complete = backend.complete_chain(
        bundle,
        conn_opts.timeout,
        anchors=backend.trust_anchors(conn_opts.cafile, conn_opts.capath),
    )
    to_write = chain
    if not complete:
        last = common_name(chain[-1].subject)
        print(
            f"warning: chain incomplete: no issuer found for '{last}'",
            file=sys.stderr,
        )
    elif len(chain) > 1 and not export_opts.include_root:
        to_write = chain[:-1]
    with open(export_opts.export_chain, "wb") as f:
        f.writelines(to_pem(c) for c in to_write)
    return chain


def _check_chain(
    info: CertificateInfo,
    target: str | None,
    port: int,
    cert: Any,
    conn: ConnectionInfo | None,
    opts: InspectOptions,
    file_bundle: list | None,
    inline_verify: tuple[bool, str | None, list] | None,
    backend: InspectionBackend,
) -> tuple[ExitCode | None, list]:
    """Verify the chain and record the outcome on ``info``."""
    if not opts.verify:
        return None, []
    if opts.file and file_bundle is not None:
        trusted, reason, verified = backend.verify_chain_offline(
            file_bundle, cafile=opts.cafile, capath=opts.capath
        )
        presented: list | None = file_bundle
    elif target:
        if inline_verify is not None:
            trusted, reason, verified = inline_verify
        else:
            conn_opts = opts.connection
            verify_kwargs = conn_opts.to_kwargs(include_ca=True)
            trusted, reason, verified = retry_network(
                lambda: backend.verify_chain(
                    target, port, conn_opts.timeouts, **verify_kwargs
                ),
                conn_opts.retries,
            )
        presented = conn.get("chain") if conn else None
        if trusted and verified and verified[0] != cert:
            trusted, verified = False, []
            reason = (
                "the server presented a different certificate on the "
                "verification handshake"
            )
    else:
        return None, []

    info["chain_trusted"] = trusted
    info["chain_error"] = reason
    if trusted:
        return None, verified
    diagnosis = diagnose_chain(presented) if presented else None
    if diagnosis:
        info["chain_diagnosis"] = diagnosis
    return ExitCode.UNTRUSTED_OR_REVOKED, verified


def _check_revocation(
    info: CertificateInfo,
    cert: Any,
    verified: list,
    timeout: float,
    backend: InspectionBackend,
) -> ExitCode | None:
    """Query OCSP/CRL and record ``revocation_status``/``revocation_detail``."""
    issuer = verified[1] if len(verified) > 1 else None
    status, detail = backend.check_revocation(cert, timeout, issuer=issuer)
    info["revocation_status"] = status
    info["revocation_detail"] = detail
    if status == RevocationStatus.REVOKED:
        return ExitCode.UNTRUSTED_OR_REVOKED
    return None


def _check_pin(info: CertificateInfo, pin: str | None) -> ExitCode | None:
    if not pin:
        return None
    info["pin_match"] = pin_matches(info, pin)
    return None if info["pin_match"] else ExitCode.PIN_MISMATCH


def _check_expect_san(
    info: CertificateInfo, expect_san: list[str] | None
) -> ExitCode | None:
    if not expect_san:
        return None
    missing = missing_san_names(info, expect_san)
    info["expected_san_missing"] = missing
    return ExitCode.SAN_MISMATCH if missing else None


def _check_policy(info: CertificateInfo, policy_opts: PolicyOptions) -> ExitCode | None:
    if not policy_opts.requested:
        return None
    not_after_max = (
        cab_forum_max_validity() if policy_opts.cab_forum else policy_opts.not_after_max
    )
    violations = policy_violations(
        info,
        not_after_max=not_after_max,
        min_key_size=policy_opts.min_key_size,
        fail_weak=policy_opts.fail_weak,
        require_sct=policy_opts.require_sct,
        require_must_staple=policy_opts.require_must_staple,
        min_tls_version=policy_opts.min_tls_version,
        require_revocation_check=policy_opts.require_revocation_check,
    )
    info["policy_violations"] = violations
    return ExitCode.POLICY if violations else None


def inspect_target(
    target: str | None,
    port: int,
    opts: InspectOptions,
    *,
    backend: InspectionBackend = _DEFAULT_BACKEND,
) -> tuple[CertificateInfo, int]:
    """Inspect one host or local file source and return ``(info, exit_code)``."""
    der, conn, inline_verify = _fetch_source(target, port, opts, backend)
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
    codes: list[ExitCode | None] = [EXIT_BY_STATUS[info["status"]]]
    if info["hostname_match"] is False:
        codes.append(ExitCode.HOSTNAME_MISMATCH)

    file_bundle: list | None = None
    if opts.file and (opts.verify or opts.chain or opts.export_chain):
        file_bundle = load_certificates(der)
    if opts.export_chain and file_bundle is not None:
        file_bundle = _export_chain(
            file_bundle, opts.export_opts, opts.connection, backend
        )

    override, chain_certs = _check_chain(
        info, target, port, cert, conn, opts, file_bundle, inline_verify, backend
    )
    codes.append(override)
    if opts.verify and target:
        codes.append(_check_revocation(info, cert, chain_certs, opts.timeout, backend))

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
        _check_pin(info, opts.pin),
        _check_expect_san(info, opts.expect_san),
        _check_policy(info, opts.policy),
    ]
    return info, most_severe(code for code in codes if code is not None)


def default_backend_for(
    *,
    get_server_cert_fn: Callable[..., tuple[bytes, ConnectionInfo]],
    verify_chain_fn: Callable[..., tuple[bool, str | None, list]],
    verify_chain_offline_fn: Callable[..., tuple[bool, str | None, list]],
    trust_anchors_fn: Callable[..., list],
    check_revocation_fn: Callable[..., tuple[RevocationStatus, str | None]],
    complete_chain_fn: Callable[..., tuple[list, bool]],
) -> InspectionBackend:
    """Build a backend using single-handshake mode unless fetch/verify are patched."""
    use_single_handshake = (
        get_server_cert_fn is _fetch_mod.get_server_cert
        and verify_chain_fn is _fetch_mod.verify_chain
    )
    return InspectionBackend(
        get_server_cert=get_server_cert_fn,
        verify_chain=verify_chain_fn,
        fetch_verified_cert=(
            _fetch_mod.fetch_verified_cert if use_single_handshake else None
        ),
        verify_chain_offline=verify_chain_offline_fn,
        trust_anchors=trust_anchors_fn,
        check_revocation=check_revocation_fn,
        complete_chain=complete_chain_fn,
    )


__all__ = [
    "ConnectionOptions",
    "ExportOptions",
    "InspectOptions",
    "InspectionBackend",
    "PolicyOptions",
    "default_backend_for",
    "inspect_target",
]
