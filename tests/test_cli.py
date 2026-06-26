"""Tests for the cli module: build_parser and main."""

import json

import pytest

from certinspect.cli import _split_target, build_parser, main

# Connection info returned by the patched network fetch.
CONN = {"tls_version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384"}


def _const_fetch(cert_bytes):
    """Return a get_server_cert replacement yielding a fixed certificate."""
    return lambda host, port, timeout, starttls=None: (cert_bytes, CONN)


def test_build_parser_defaults():
    args = build_parser().parse_args(["example.com"])
    assert args.target == ["example.com"]
    assert args.port == 443
    assert args.file is None
    assert args.json is False


def test_build_parser_options():
    args = build_parser().parse_args(["--file", "cert.pem", "--port", "8443", "--json"])
    assert args.file == "cert.pem"
    assert args.port == 8443
    assert args.json is True
    assert args.target == []


def test_build_parser_multiple_targets():
    args = build_parser().parse_args(["a.com", "b.com", "c.com"])
    assert args.target == ["a.com", "b.com", "c.com"]


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("example.com", ("example.com", 443)),
        ("https://example.com", ("example.com", 443)),
        ("https://example.com/", ("example.com", 443)),
        ("https://example.com/path?q=1", ("example.com", 443)),
        ("http://example.com:8443/x", ("example.com", 8443)),
        ("example.com:8443", ("example.com", 8443)),
    ],
)
def test_split_target(raw, expected):
    assert _split_target(raw, 443) == expected


def _run_main(monkeypatch, argv):
    """Run main() with the given argv and return the exit code."""
    monkeypatch.setattr("sys.argv", ["certinspect", *argv])
    with pytest.raises(SystemExit) as exc:
        main()
    code = exc.value.code
    return 0 if code is None else code


def test_main_file_human_output(monkeypatch, capsys, tmp_path, make_cert):
    cert_path = tmp_path / "cert.der"
    cert_path.write_bytes(make_cert())

    code = _run_main(monkeypatch, ["--file", str(cert_path)])

    out = capsys.readouterr().out
    assert code == 0
    assert "Subject:" in out
    assert "CN=example.com" in out


def test_main_file_json_output(monkeypatch, capsys, tmp_path, make_cert):
    cert_path = tmp_path / "cert.der"
    cert_path.write_bytes(make_cert())

    code = _run_main(monkeypatch, ["--file", str(cert_path), "--json"])

    assert code == 0
    data = json.loads(capsys.readouterr().out)
    assert data[0]["subject"] == "CN=example.com"


def test_main_no_target_and_no_file_exits(monkeypatch, capsys):
    code = _run_main(monkeypatch, [])
    assert code == 2
    assert "no target" in capsys.readouterr().err.lower()


def test_main_missing_file_exits(monkeypatch, capsys, tmp_path):
    missing = tmp_path / "does_not_exist.pem"
    code = _run_main(monkeypatch, ["--file", str(missing)])
    assert code == 1
    assert "error" in capsys.readouterr().err.lower()


def test_main_invalid_certificate_file_exits(monkeypatch, capsys, tmp_path):
    bad = tmp_path / "bad.pem"
    bad.write_bytes(b"not a certificate")
    code = _run_main(monkeypatch, ["--file", str(bad)])
    assert code == 1


def test_main_exit_code_valid(monkeypatch, capsys, tmp_path, make_cert):
    cert_path = tmp_path / "cert.der"
    cert_path.write_bytes(make_cert(days_valid=90))
    code = _run_main(monkeypatch, ["--file", str(cert_path)])
    assert code == 0


def test_main_exit_code_expiring(monkeypatch, capsys, tmp_path, make_cert):
    cert_path = tmp_path / "cert.der"
    cert_path.write_bytes(make_cert(days_valid=10))
    code = _run_main(monkeypatch, ["--file", str(cert_path), "--days", "30"])
    assert code == 3


def test_main_exit_code_expired(monkeypatch, capsys, tmp_path, make_cert):
    cert_path = tmp_path / "cert.der"
    cert_path.write_bytes(make_cert(days_valid=-5, days_ago_start=365))
    code = _run_main(monkeypatch, ["--file", str(cert_path)])
    assert code == 4


def test_main_hostname_match_exit_zero(monkeypatch, capsys, make_cert):
    monkeypatch.setattr(
        "certinspect.cli.get_server_cert",
        _const_fetch(make_cert(san=["example.com"])),
    )
    code = _run_main(monkeypatch, ["example.com"])
    assert code == 0
    assert "Hostname match:" in capsys.readouterr().out


def test_main_hostname_mismatch_exit_five(monkeypatch, capsys, make_cert):
    monkeypatch.setattr(
        "certinspect.cli.get_server_cert",
        _const_fetch(make_cert(san=["example.com"])),
    )
    code = _run_main(monkeypatch, ["other.com"])
    assert code == 5


def test_main_url_target_is_normalized(monkeypatch, capsys, make_cert):
    seen = {}

    def _fetch(host, port, timeout, starttls=None):
        seen["host"], seen["port"] = host, port
        return make_cert(san=["example.com"]), CONN

    monkeypatch.setattr("certinspect.cli.get_server_cert", _fetch)
    code = _run_main(monkeypatch, ["https://example.com:8443/path"])
    assert code == 0
    assert seen == {"host": "example.com", "port": 8443}
    assert "=== example.com ===" in capsys.readouterr().out


def test_main_hostname_match_in_json(monkeypatch, capsys, make_cert):
    monkeypatch.setattr(
        "certinspect.cli.get_server_cert",
        _const_fetch(make_cert(san=["example.com"])),
    )
    _run_main(monkeypatch, ["example.com", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data[0]["hostname_match"] is True


def test_main_file_hostname_match_is_null(monkeypatch, capsys, tmp_path, make_cert):
    cert_path = tmp_path / "cert.der"
    cert_path.write_bytes(make_cert())
    _run_main(monkeypatch, ["--file", str(cert_path), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data[0]["hostname_match"] is None


def test_main_export_writes_pem(monkeypatch, capsys, tmp_path, make_cert):
    cert_path = tmp_path / "cert.der"
    cert_path.write_bytes(make_cert())
    out_path = tmp_path / "exported.pem"
    code = _run_main(monkeypatch, ["--file", str(cert_path), "--export", str(out_path)])
    assert code == 0
    content = out_path.read_bytes()
    assert content.startswith(b"-----BEGIN CERTIFICATE-----")


def _fake_fetch(mapping):
    """Return a get_server_cert replacement backed by host->bytes mapping."""

    def _fetch(host, port, timeout, starttls=None):
        return mapping[host], CONN

    return _fetch


def test_main_batch_human_has_headers(monkeypatch, capsys, make_cert):
    certs = {
        "a.com": make_cert(san=["a.com"]),
        "b.com": make_cert(san=["b.com"]),
    }
    monkeypatch.setattr("certinspect.cli.get_server_cert", _fake_fetch(certs))
    code = _run_main(monkeypatch, ["a.com", "b.com"])
    out = capsys.readouterr().out
    assert "=== a.com ===" in out
    assert "=== b.com ===" in out
    assert code == 0


def test_main_batch_json_is_list(monkeypatch, capsys, make_cert):
    certs = {
        "a.com": make_cert(common_name="a.com", san=["a.com"]),
        "b.com": make_cert(common_name="b.com", san=["b.com"]),
    }
    monkeypatch.setattr("certinspect.cli.get_server_cert", _fake_fetch(certs))
    _run_main(monkeypatch, ["a.com", "b.com", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert isinstance(data, list)
    assert {item["subject"] for item in data} == {"CN=a.com", "CN=b.com"}


def test_main_batch_worst_exit_code(monkeypatch, capsys, make_cert):
    # One valid cert and one expired -> worst code wins (4).
    certs = {
        "good.com": make_cert(san=["good.com"], days_valid=200),
        "bad.com": make_cert(san=["bad.com"], days_valid=-5, days_ago_start=365),
    }
    monkeypatch.setattr("certinspect.cli.get_server_cert", _fake_fetch(certs))
    code = _run_main(monkeypatch, ["good.com", "bad.com"])
    assert code == 4


def test_main_batch_continues_on_error(monkeypatch, capsys, make_cert):
    certs = {"ok.com": make_cert(san=["ok.com"], days_valid=200)}

    def _fetch(host, port, timeout, starttls=None):
        if host == "down.com":
            raise OSError("connection refused")
        return certs[host], CONN

    monkeypatch.setattr("certinspect.cli.get_server_cert", _fetch)
    code = _run_main(monkeypatch, ["down.com", "ok.com"])
    captured = capsys.readouterr()
    # The reachable host is still inspected despite the failing one.
    assert "ok.com" in captured.out
    assert "down.com" in captured.err
    assert code == 1


def test_main_version_flag(monkeypatch, capsys):
    from certinspect import __version__

    code = _run_main(monkeypatch, ["--version"])
    assert code == 0
    assert __version__ in capsys.readouterr().out


def test_main_shows_tls_info(monkeypatch, capsys, make_cert):
    monkeypatch.setattr(
        "certinspect.cli.get_server_cert",
        _const_fetch(make_cert(san=["example.com"])),
    )
    _run_main(monkeypatch, ["example.com"])
    out = capsys.readouterr().out
    assert "TLS version:" in out
    assert "TLSv1.3" in out


def test_main_tls_info_in_json(monkeypatch, capsys, make_cert):
    monkeypatch.setattr(
        "certinspect.cli.get_server_cert",
        _const_fetch(make_cert(san=["example.com"])),
    )
    _run_main(monkeypatch, ["example.com", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data[0]["tls_version"] == "TLSv1.3"
    assert data[0]["cipher"] == "TLS_AES_256_GCM_SHA384"


def test_main_file_has_no_tls_info(monkeypatch, capsys, tmp_path, make_cert):
    cert_path = tmp_path / "cert.der"
    cert_path.write_bytes(make_cert())
    _run_main(monkeypatch, ["--file", str(cert_path), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert "tls_version" not in data[0]


def test_main_quiet_suppresses_valid(monkeypatch, capsys, tmp_path, make_cert):
    cert_path = tmp_path / "cert.der"
    cert_path.write_bytes(make_cert(days_valid=200))
    code = _run_main(monkeypatch, ["--file", str(cert_path), "--quiet"])
    assert code == 0
    assert capsys.readouterr().out == ""


def test_main_quiet_shows_problem(monkeypatch, capsys, tmp_path, make_cert):
    cert_path = tmp_path / "cert.der"
    cert_path.write_bytes(make_cert(days_valid=10))
    code = _run_main(monkeypatch, ["--file", str(cert_path), "--quiet", "--days", "30"])
    assert code == 3
    assert "Status:" in capsys.readouterr().out


def test_main_verify_trusted_exit_zero(monkeypatch, capsys, make_cert):
    monkeypatch.setattr(
        "certinspect.cli.get_server_cert",
        _const_fetch(make_cert(san=["example.com"])),
    )
    monkeypatch.setattr(
        "certinspect.cli.verify_chain",
        lambda host, port, timeout, starttls=None, cafile=None, capath=None: (
            True,
            None,
            [],
        ),
    )
    monkeypatch.setattr(
        "certinspect.cli.check_revocation",
        lambda cert, timeout, issuer=None: ("GOOD", None),
    )
    code = _run_main(monkeypatch, ["example.com", "--verify"])
    out = capsys.readouterr().out
    assert code == 0
    assert "Chain trusted:" in out
    assert "Revocation:" in out


def test_main_verify_untrusted_exit_six(monkeypatch, capsys, make_cert):
    monkeypatch.setattr(
        "certinspect.cli.get_server_cert",
        _const_fetch(make_cert(san=["example.com"])),
    )
    monkeypatch.setattr(
        "certinspect.cli.verify_chain",
        lambda host, port, timeout, starttls=None, cafile=None, capath=None: (
            False,
            "self signed certificate",
            [],
        ),
    )
    monkeypatch.setattr(
        "certinspect.cli.check_revocation",
        lambda cert, timeout, issuer=None: (
            "UNAVAILABLE",
            "no OCSP responder in AIA extension",
        ),
    )
    code = _run_main(monkeypatch, ["example.com", "--verify"])
    out = capsys.readouterr().out
    assert code == 6
    assert "Chain trusted:" in out
    assert "self signed certificate" in out


def test_main_verify_in_json(monkeypatch, capsys, make_cert):
    monkeypatch.setattr(
        "certinspect.cli.get_server_cert",
        _const_fetch(make_cert(san=["example.com"])),
    )
    monkeypatch.setattr(
        "certinspect.cli.verify_chain",
        lambda host, port, timeout, starttls=None, cafile=None, capath=None: (
            True,
            None,
            [],
        ),
    )
    monkeypatch.setattr(
        "certinspect.cli.check_revocation",
        lambda cert, timeout, issuer=None: ("GOOD", None),
    )
    _run_main(monkeypatch, ["example.com", "--verify", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data[0]["chain_trusted"] is True
    assert data[0]["revocation_status"] == "GOOD"


def test_main_verify_revoked_exit_six(monkeypatch, capsys, make_cert):
    monkeypatch.setattr(
        "certinspect.cli.get_server_cert",
        _const_fetch(make_cert(san=["example.com"])),
    )
    monkeypatch.setattr(
        "certinspect.cli.verify_chain",
        lambda host, port, timeout, starttls=None, cafile=None, capath=None: (
            True,
            None,
            [],
        ),
    )
    monkeypatch.setattr(
        "certinspect.cli.check_revocation",
        lambda cert, timeout, issuer=None: (
            "REVOKED",
            "revoked at 2026-01-01 00:00:00",
        ),
    )
    code = _run_main(monkeypatch, ["example.com", "--verify"])
    out = capsys.readouterr().out
    assert code == 6
    assert "Revocation:" in out
    assert "certificate revoked" in out


def test_main_verify_revocation_unavailable_is_soft_fail(
    monkeypatch, capsys, make_cert
):
    monkeypatch.setattr(
        "certinspect.cli.get_server_cert",
        _const_fetch(make_cert(san=["example.com"])),
    )
    monkeypatch.setattr(
        "certinspect.cli.verify_chain",
        lambda host, port, timeout, starttls=None, cafile=None, capath=None: (
            True,
            None,
            [],
        ),
    )
    monkeypatch.setattr(
        "certinspect.cli.check_revocation",
        lambda cert, timeout, issuer=None: ("UNAVAILABLE", "OCSP request failed"),
    )
    code = _run_main(monkeypatch, ["example.com", "--verify"])
    assert code == 0


def test_main_file_verify_is_skipped(monkeypatch, capsys, tmp_path, make_cert):
    cert_path = tmp_path / "cert.der"
    cert_path.write_bytes(make_cert())
    _run_main(monkeypatch, ["--file", str(cert_path), "--verify", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert "chain_trusted" not in data[0]


def _fingerprint(cert_bytes):
    from certinspect.parser import analyze, load_certificate

    return analyze(load_certificate(cert_bytes))["fingerprint_sha256"]


def test_main_pin_match_exit_zero(monkeypatch, capsys, make_cert):
    cert = make_cert(san=["example.com"])
    monkeypatch.setattr("certinspect.cli.get_server_cert", _const_fetch(cert))
    code = _run_main(monkeypatch, ["example.com", "--pin", _fingerprint(cert)])
    out = capsys.readouterr().out
    assert code == 0
    assert "Pin match:" in out


def test_main_pin_mismatch_exit_seven(monkeypatch, capsys, make_cert):
    cert = make_cert(san=["example.com"])
    monkeypatch.setattr("certinspect.cli.get_server_cert", _const_fetch(cert))
    code = _run_main(monkeypatch, ["example.com", "--pin", "00:11:22:33"])
    out = capsys.readouterr().out
    assert code == 7
    assert "does not match the expected pin" in out


def test_main_pin_ignores_colons_and_case(monkeypatch, capsys, make_cert):
    cert = make_cert(san=["example.com"])
    monkeypatch.setattr("certinspect.cli.get_server_cert", _const_fetch(cert))
    pin = _fingerprint(cert).replace(":", "").lower()
    code = _run_main(monkeypatch, ["example.com", "--pin", pin])
    assert code == 0


def test_main_chain_shows_chain(monkeypatch, capsys, make_cert):
    cert = make_cert(san=["example.com"])
    monkeypatch.setattr("certinspect.cli.get_server_cert", _const_fetch(cert))
    code = _run_main(monkeypatch, ["example.com", "--chain"])
    out = capsys.readouterr().out
    assert code == 0
    assert "Certificate chain:" in out
    assert "[0] CN=example.com" in out


def test_main_chain_in_json(monkeypatch, capsys, make_cert):
    cert = make_cert(san=["example.com"])
    monkeypatch.setattr("certinspect.cli.get_server_cert", _const_fetch(cert))
    _run_main(monkeypatch, ["example.com", "--chain", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data[0]["chain"][0]["subject"] == "CN=example.com"


def test_main_input_reads_targets_from_file(monkeypatch, capsys, tmp_path, make_cert):
    certs = {
        "a.com": make_cert(san=["a.com"]),
        "b.com": make_cert(san=["b.com"]),
    }
    monkeypatch.setattr("certinspect.cli.get_server_cert", _fake_fetch(certs))
    hosts = tmp_path / "hosts.txt"
    hosts.write_text("# comment\na.com\n\nb.com\n")
    code = _run_main(monkeypatch, ["--input", str(hosts)])
    out = capsys.readouterr().out
    assert code == 0
    assert "=== a.com ===" in out
    assert "=== b.com ===" in out


def test_main_input_reads_targets_from_stdin(monkeypatch, capsys, make_cert):
    import io

    monkeypatch.setattr(
        "certinspect.cli.get_server_cert",
        _const_fetch(make_cert(san=["example.com"])),
    )
    monkeypatch.setattr("sys.stdin", io.StringIO("example.com\n"))
    code = _run_main(monkeypatch, ["--input", "-"])
    assert code == 0
    assert "CN=example.com" in capsys.readouterr().out


def test_main_exporter_nagios_ok(monkeypatch, capsys, make_cert):
    monkeypatch.setattr(
        "certinspect.cli.get_server_cert",
        _const_fetch(make_cert(san=["example.com"], days_valid=200)),
    )
    code = _run_main(monkeypatch, ["example.com", "--exporter", "nagios"])
    out = capsys.readouterr().out
    assert code == 0
    assert out.startswith("OK: example.com")
    assert "| days=" in out


def test_main_exporter_nagios_expiring_exits_warning(monkeypatch, capsys, make_cert):
    monkeypatch.setattr(
        "certinspect.cli.get_server_cert",
        _const_fetch(make_cert(san=["example.com"], days_valid=10)),
    )
    code = _run_main(
        monkeypatch, ["example.com", "--exporter", "nagios", "--days", "30"]
    )
    assert code == 1
    assert "WARNING" in capsys.readouterr().out


def test_main_exporter_nagios_unreachable_is_critical(monkeypatch, capsys, make_cert):
    def _fetch(host, port, timeout, starttls=None):
        if host == "down.com":
            raise OSError("connection refused")
        return make_cert(san=["ok.com"], days_valid=200), CONN

    monkeypatch.setattr("certinspect.cli.get_server_cert", _fetch)
    code = _run_main(monkeypatch, ["ok.com", "down.com", "--exporter", "nagios"])
    captured = capsys.readouterr()
    assert code == 2
    assert "CRITICAL: down.com unreachable" in captured.out
    # With an exporter, per-host errors are not duplicated on stderr.
    assert captured.err == ""


def test_main_exporter_prometheus_metrics(monkeypatch, capsys, make_cert):
    monkeypatch.setattr(
        "certinspect.cli.get_server_cert",
        _const_fetch(make_cert(san=["example.com"], days_valid=42)),
    )
    code = _run_main(monkeypatch, ["example.com", "--exporter", "prometheus"])
    out = capsys.readouterr().out
    # Prometheus output keeps the normal worst-status exit code.
    assert code == 0
    assert "# TYPE certinspect_cert_expiry_days gauge" in out
    assert 'certinspect_up{target="example.com"} 1' in out


def test_main_exporter_rejects_json(monkeypatch, capsys, make_cert):
    monkeypatch.setattr(
        "certinspect.cli.get_server_cert",
        _const_fetch(make_cert(san=["example.com"])),
    )
    code = _run_main(monkeypatch, ["example.com", "--exporter", "nagios", "--json"])
    assert code == 2
    assert "cannot be used together" in capsys.readouterr().err


def _capturing_fetch(seen, cert_bytes):
    """A get_server_cert replacement that records port and starttls."""

    def _fetch(host, port, timeout, starttls=None):
        seen["port"], seen["starttls"] = port, starttls
        return cert_bytes, CONN

    return _fetch


def test_main_starttls_uses_protocol_default_port(monkeypatch, capsys, make_cert):
    seen = {}
    monkeypatch.setattr(
        "certinspect.cli.get_server_cert",
        _capturing_fetch(seen, make_cert(san=["mail.example.com"])),
    )
    _run_main(monkeypatch, ["mail.example.com", "--starttls", "smtp"])
    assert seen == {"port": 587, "starttls": "smtp"}


def test_main_starttls_explicit_port_overrides_default(monkeypatch, capsys, make_cert):
    seen = {}
    monkeypatch.setattr(
        "certinspect.cli.get_server_cert",
        _capturing_fetch(seen, make_cert(san=["mail.example.com"])),
    )
    _run_main(monkeypatch, ["mail.example.com", "--starttls", "imap", "--port", "1143"])
    assert seen == {"port": 1143, "starttls": "imap"}


def test_main_starttls_port_from_target_overrides_default(
    monkeypatch, capsys, make_cert
):
    seen = {}
    monkeypatch.setattr(
        "certinspect.cli.get_server_cert",
        _capturing_fetch(seen, make_cert(san=["mail.example.com"])),
    )
    _run_main(monkeypatch, ["mail.example.com:25", "--starttls", "smtp"])
    assert seen == {"port": 25, "starttls": "smtp"}


def test_main_starttls_rejects_invalid_protocol(monkeypatch, capsys):
    code = _run_main(monkeypatch, ["example.com", "--starttls", "xmpp"])
    assert code == 2
    assert "invalid choice" in capsys.readouterr().err


def test_build_parser_concurrency_default():
    args = build_parser().parse_args(["example.com"])
    assert args.concurrency == 1


def test_main_concurrency_preserves_order(monkeypatch, capsys, make_cert):
    hosts = ["a.com", "b.com", "c.com", "d.com"]
    certs = {h: make_cert(san=[h]) for h in hosts}
    monkeypatch.setattr("certinspect.cli.get_server_cert", _fake_fetch(certs))
    code = _run_main(monkeypatch, [*hosts, "--concurrency", "3"])
    out = capsys.readouterr().out
    assert code == 0
    positions = [out.index(f"=== {h} ===") for h in hosts]
    assert positions == sorted(positions)


def test_main_concurrency_runs_in_parallel(monkeypatch, capsys, make_cert):
    import threading

    # The barrier only releases when both fetches are in flight at once, so
    # the test would time out (BrokenBarrierError) if execution were serial.
    barrier = threading.Barrier(2, timeout=5)
    certs = {"a.com": make_cert(san=["a.com"]), "b.com": make_cert(san=["b.com"])}

    def _fetch(host, port, timeout, starttls=None):
        barrier.wait()
        return certs[host], CONN

    monkeypatch.setattr("certinspect.cli.get_server_cert", _fetch)
    code = _run_main(monkeypatch, ["a.com", "b.com", "--concurrency", "2"])
    assert code == 0
    assert not barrier.broken


def test_main_concurrency_one_is_serial(monkeypatch, capsys, make_cert):
    certs = {"a.com": make_cert(san=["a.com"]), "b.com": make_cert(san=["b.com"])}
    monkeypatch.setattr("certinspect.cli.get_server_cert", _fake_fetch(certs))
    code = _run_main(monkeypatch, ["a.com", "b.com", "--concurrency", "1"])
    out = capsys.readouterr().out
    assert code == 0
    assert "=== a.com ===" in out
    assert "=== b.com ===" in out


def test_main_csv_output(monkeypatch, capsys, make_cert):
    import csv
    import io

    certs = {"a.com": make_cert(san=["a.com"]), "b.com": make_cert(san=["b.com"])}
    monkeypatch.setattr("certinspect.cli.get_server_cert", _fake_fetch(certs))
    code = _run_main(monkeypatch, ["a.com", "b.com", "--csv"])
    out = capsys.readouterr().out
    assert code == 0
    rows = list(csv.DictReader(io.StringIO(out)))
    assert [r["target"] for r in rows] == ["a.com", "b.com"]
    assert rows[0]["status"] == "VALID"


def test_main_csv_custom_delimiter(monkeypatch, capsys, make_cert):
    import csv
    import io

    certs = {"a.com": make_cert(san=["a.com"])}
    monkeypatch.setattr("certinspect.cli.get_server_cert", _fake_fetch(certs))
    code = _run_main(monkeypatch, ["a.com", "--csv", "--csv-delimiter", ";"])
    out = capsys.readouterr().out
    assert code == 0
    rows = list(csv.DictReader(io.StringIO(out), delimiter=";"))
    assert rows[0]["target"] == "a.com"


def test_main_csv_delimiter_rejects_multichar(monkeypatch, capsys, make_cert):
    code = _run_main(monkeypatch, ["a.com", "--csv", "--csv-delimiter", ";;"])
    assert code == 2
    assert "single character" in capsys.readouterr().err


def test_main_csv_rejects_json(monkeypatch, capsys, make_cert):
    code = _run_main(monkeypatch, ["a.com", "--csv", "--json"])
    assert code == 2
    assert "cannot be used together" in capsys.readouterr().err


def test_main_csv_rejects_exporter(monkeypatch, capsys, make_cert):
    code = _run_main(monkeypatch, ["a.com", "--csv", "--exporter", "nagios"])
    assert code == 2
    assert "cannot be used together" in capsys.readouterr().err


def test_main_cafile_requires_verify(monkeypatch, capsys):
    code = _run_main(monkeypatch, ["example.com", "--cafile", "/tmp/ca.pem"])
    assert code == 2
    assert "require --verify" in capsys.readouterr().err


def test_main_capath_requires_verify(monkeypatch, capsys):
    code = _run_main(monkeypatch, ["example.com", "--capath", "/tmp/certs"])
    assert code == 2
    assert "require --verify" in capsys.readouterr().err


def test_main_cafile_forwarded_to_verify_chain(monkeypatch, capsys, make_cert):
    monkeypatch.setattr(
        "certinspect.cli.get_server_cert",
        _const_fetch(make_cert(san=["example.com"])),
    )
    recorded = {}

    def _fake_verify(host, port, timeout, starttls=None, cafile=None, capath=None):
        recorded["cafile"] = cafile
        recorded["capath"] = capath
        return True, None, []

    monkeypatch.setattr("certinspect.cli.verify_chain", _fake_verify)
    monkeypatch.setattr(
        "certinspect.cli.check_revocation",
        lambda cert, timeout, issuer=None: ("GOOD", None),
    )
    code = _run_main(
        monkeypatch,
        [
            "example.com",
            "--verify",
            "--cafile",
            "/tmp/ca.pem",
            "--capath",
            "/tmp/certs",
        ],
    )
    assert code == 0
    assert recorded == {"cafile": "/tmp/ca.pem", "capath": "/tmp/certs"}


def test_main_max_days_filters_output(monkeypatch, capsys, make_cert):
    certs = {
        "soon.com": make_cert(san=["soon.com"], days_valid=10),
        "later.com": make_cert(san=["later.com"], days_valid=200),
    }
    monkeypatch.setattr("certinspect.cli.get_server_cert", _fake_fetch(certs))
    code = _run_main(monkeypatch, ["soon.com", "later.com", "--max-days", "30"])
    out = capsys.readouterr().out
    assert "=== soon.com ===" in out
    assert "=== later.com ===" not in out
    # soon.com is EXPIRING (code 3); the filter hides later.com from the output
    # but the exit code still reflects every inspected target.
    assert code == 3


def test_main_max_days_keeps_expired(monkeypatch, capsys, make_cert):
    certs = {
        "expired.com": make_cert(
            san=["expired.com"], days_valid=-5, days_ago_start=365
        ),
        "later.com": make_cert(san=["later.com"], days_valid=200),
    }
    monkeypatch.setattr("certinspect.cli.get_server_cert", _fake_fetch(certs))
    code = _run_main(monkeypatch, ["expired.com", "later.com", "--max-days", "30"])
    out = capsys.readouterr().out
    assert "=== expired.com ===" in out
    assert "=== later.com ===" not in out
    # An expired certificate still drives the exit code even when filtered in.
    assert code == 4


def test_main_max_days_applies_to_csv(monkeypatch, capsys, make_cert):
    import csv
    import io

    certs = {
        "soon.com": make_cert(san=["soon.com"], days_valid=10),
        "later.com": make_cert(san=["later.com"], days_valid=200),
    }
    monkeypatch.setattr("certinspect.cli.get_server_cert", _fake_fetch(certs))
    _run_main(monkeypatch, ["soon.com", "later.com", "--max-days", "30", "--csv"])
    out = capsys.readouterr().out
    rows = list(csv.DictReader(io.StringIO(out)))
    assert [r["target"] for r in rows] == ["soon.com"]


def test_main_sort_host_orders_alphabetically(monkeypatch, capsys, make_cert):
    certs = {
        "b.com": make_cert(san=["b.com"]),
        "a.com": make_cert(san=["a.com"]),
    }
    monkeypatch.setattr("certinspect.cli.get_server_cert", _fake_fetch(certs))
    _run_main(monkeypatch, ["b.com", "a.com", "--sort", "host"])
    out = capsys.readouterr().out
    assert out.index("=== a.com ===") < out.index("=== b.com ===")


def test_main_sort_expiry_soonest_first(monkeypatch, capsys, make_cert):
    import csv
    import io

    certs = {
        "later.com": make_cert(san=["later.com"], days_valid=200),
        "soon.com": make_cert(san=["soon.com"], days_valid=10),
    }
    monkeypatch.setattr("certinspect.cli.get_server_cert", _fake_fetch(certs))
    _run_main(monkeypatch, ["later.com", "soon.com", "--sort", "expiry", "--csv"])
    out = capsys.readouterr().out
    rows = list(csv.DictReader(io.StringIO(out)))
    assert [r["target"] for r in rows] == ["soon.com", "later.com"]


def test_main_sort_does_not_change_exit_code(monkeypatch, capsys, make_cert):
    certs = {
        "ok.com": make_cert(san=["ok.com"], days_valid=200),
        "soon.com": make_cert(san=["soon.com"], days_valid=10),
    }
    monkeypatch.setattr("certinspect.cli.get_server_cert", _fake_fetch(certs))
    code = _run_main(monkeypatch, ["ok.com", "soon.com", "--sort", "host"])
    # soon.com is EXPIRING (code 3); sorting must not alter the exit code.
    assert code == 3


def test_main_summary_goes_to_stderr(monkeypatch, capsys, make_cert):
    certs = {
        "ok.com": make_cert(san=["ok.com"], days_valid=200),
        "soon.com": make_cert(san=["soon.com"], days_valid=10),
    }
    monkeypatch.setattr("certinspect.cli.get_server_cert", _fake_fetch(certs))
    _run_main(monkeypatch, ["ok.com", "soon.com", "--summary"])
    captured = capsys.readouterr()
    assert "summary: 1 valid · 1 expiring · 0 expired (2 targets)" in captured.err
    # The report itself stays on stdout, untouched by the summary line.
    assert "summary:" not in captured.out


def test_main_summary_counts_before_filtering(monkeypatch, capsys, make_cert):
    certs = {
        "soon.com": make_cert(san=["soon.com"], days_valid=10),
        "later.com": make_cert(san=["later.com"], days_valid=200),
    }
    monkeypatch.setattr("certinspect.cli.get_server_cert", _fake_fetch(certs))
    _run_main(monkeypatch, ["soon.com", "later.com", "--max-days", "30", "--summary"])
    err = capsys.readouterr().err
    # later.com is filtered out of the report but still counted in the summary.
    assert "1 valid" in err
    assert "1 expiring" in err
    assert "(2 targets)" in err


def test_main_summary_with_csv_keeps_csv_clean(monkeypatch, capsys, make_cert):
    import csv
    import io

    certs = {"a.com": make_cert(san=["a.com"], days_valid=200)}
    monkeypatch.setattr("certinspect.cli.get_server_cert", _fake_fetch(certs))
    _run_main(monkeypatch, ["a.com", "--csv", "--summary"])
    captured = capsys.readouterr()
    assert "summary:" in captured.err
    rows = list(csv.DictReader(io.StringIO(captured.out)))
    assert [r["target"] for r in rows] == ["a.com"]


def test_main_critical_days_exit_four(monkeypatch, capsys, make_cert):
    certs = {"soon.com": make_cert(san=["soon.com"], days_valid=3)}
    monkeypatch.setattr("certinspect.cli.get_server_cert", _fake_fetch(certs))
    code = _run_main(monkeypatch, ["soon.com", "--critical-days", "7"])
    out = capsys.readouterr().out
    # Inside the critical window: status CRITICAL and exit code 4.
    assert "Status:         CRITICAL" in out
    assert code == 4


def test_main_critical_days_warning_stays_three(monkeypatch, capsys, make_cert):
    certs = {"soon.com": make_cert(san=["soon.com"], days_valid=20)}
    monkeypatch.setattr("certinspect.cli.get_server_cert", _fake_fetch(certs))
    code = _run_main(monkeypatch, ["soon.com", "--critical-days", "7"])
    # Past the critical window but within the default 30-day warning window.
    assert code == 3


def test_main_critical_days_must_not_exceed_days(monkeypatch, capsys, make_cert):
    code = _run_main(monkeypatch, ["a.com", "--days", "10", "--critical-days", "20"])
    assert code == 2
    assert "less than or equal to --days" in capsys.readouterr().err


def test_main_critical_days_in_summary(monkeypatch, capsys, make_cert):
    certs = {"soon.com": make_cert(san=["soon.com"], days_valid=3)}
    monkeypatch.setattr("certinspect.cli.get_server_cert", _fake_fetch(certs))
    _run_main(monkeypatch, ["soon.com", "--critical-days", "7", "--summary"])
    assert "1 critical" in capsys.readouterr().err
