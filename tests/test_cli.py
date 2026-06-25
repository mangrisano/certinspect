"""Tests for the cli module: build_parser and main."""

import json

import pytest

from certinspect.cli import build_parser, main

# Connection info returned by the patched network fetch.
CONN = {"tls_version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384"}


def _const_fetch(cert_bytes):
    """Return a get_server_cert replacement yielding a fixed certificate."""
    return lambda host, port, timeout: (cert_bytes, CONN)


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

    def _fetch(host, port, timeout):
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

    def _fetch(host, port, timeout):
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
        lambda host, port, timeout: (True, None, []),
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
        lambda host, port, timeout: (False, "self signed certificate", []),
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
        lambda host, port, timeout: (True, None, []),
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
        lambda host, port, timeout: (True, None, []),
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
        lambda host, port, timeout: (True, None, []),
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
