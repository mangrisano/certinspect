"""Tests for the formatter module: format_human and format_json."""

import json

import pytest

from certinspect.formatter import (
    NAGIOS_CRITICAL,
    NAGIOS_OK,
    NAGIOS_UNKNOWN,
    NAGIOS_WARNING,
    format_human,
    format_json,
    format_nagios,
    format_prometheus,
)
from certinspect.parser import analyze, load_certificate


def _info(cert_bytes):
    return analyze(load_certificate(cert_bytes))


def test_format_json_is_valid_json(der_cert):
    text = format_json(_info(der_cert))
    data = json.loads(text)
    assert data["subject"] == "CN=example.com"
    assert data["key_size"] == 2048


def test_format_json_serializes_dates_as_strings(der_cert):
    data = json.loads(format_json(_info(der_cert)))
    # datetime objects are rendered via default=str, i.e. as strings.
    assert isinstance(data["not_valid_before"], str)
    assert isinstance(data["not_valid_after"], str)


def test_format_json_san_is_list(der_cert):
    data = json.loads(format_json(_info(der_cert)))
    assert data["san"] == ["example.com", "www.example.com"]


def test_format_human_valid_status(make_cert):
    text = format_human(_info(make_cert(days_valid=90)))
    assert "Status:" in text
    assert "VALID" in text
    assert "EXPIRED" not in text


def test_format_human_expired_status(make_cert):
    text = format_human(_info(make_cert(days_valid=-5, days_ago_start=365)))
    assert "EXPIRED" in text


def test_format_human_warning_when_expiring_soon(make_cert):
    text = format_human(_info(make_cert(days_valid=10)))
    assert "WARNING" in text


def test_format_human_no_warning_when_far_from_expiry(make_cert):
    text = format_human(_info(make_cert(days_valid=200)))
    assert "WARNING" not in text


def test_format_human_lists_san(make_cert):
    text = format_human(_info(make_cert(san=["a.example.com", "b.example.com"])))
    assert "a.example.com" in text
    assert "b.example.com" in text


def test_format_human_handles_missing_san(make_cert):
    text = format_human(_info(make_cert(san=None)))
    assert "(none)" in text


def test_format_human_shows_fingerprint(der_cert):
    info = _info(der_cert)
    text = format_human(info)
    assert "Fingerprint:" in text
    assert info["fingerprint_sha256"] in text


def test_format_human_shows_ca_flag(make_cert):
    text = format_human(_info(make_cert(ca=True)))
    assert "CA:" in text
    assert "True" in text


def test_format_human_shows_self_signed(make_cert):
    text = format_human(_info(make_cert()))
    assert "Self-Signed:" in text


def test_format_human_warns_on_weak_key(make_cert):
    text = format_human(_info(make_cert(key_size=1024)))
    assert "WARNING" in text
    assert "key" in text.lower()


def test_format_human_no_weak_warning_for_strong_cert(make_cert):
    text = format_human(_info(make_cert(days_valid=200)))
    assert "weak" not in text.lower()


def test_format_human_status_expiring(make_cert):
    text = format_human(_info(make_cert(days_valid=10)), warn_days=30)
    assert "EXPIRING" in text


def test_format_human_warning_threshold_is_configurable(make_cert):
    text = format_human(_info(make_cert(days_valid=10)), warn_days=5)
    assert "WARNING" not in text
    assert "EXPIRING" not in text


def test_format_nagios_ok_for_valid_cert(make_cert):
    results = [("example.com", _info(make_cert(days_valid=200)), 0)]
    text, code = format_nagios(results)
    assert code == NAGIOS_OK
    assert text.startswith("OK: example.com")
    assert "| days=" in text


def test_format_nagios_warning_for_expiring(make_cert):
    results = [("example.com", _info(make_cert(days_valid=10)), 3)]
    text, code = format_nagios(results, warn_days=30)
    assert code == NAGIOS_WARNING
    assert "WARNING" in text


def test_format_nagios_critical_for_problem(make_cert):
    results = [("example.com", _info(make_cert(days_valid=-5, days_ago_start=365)), 4)]
    text, code = format_nagios(results)
    assert code == NAGIOS_CRITICAL
    assert "CRITICAL" in text


def test_format_nagios_reports_unreachable_as_critical(make_cert):
    results = [("good.example.com", _info(make_cert(days_valid=200)), 0)]
    errors = [("bad.example.com", "timed out")]
    text, code = format_nagios(results, errors)
    assert code == NAGIOS_CRITICAL
    assert "bad.example.com unreachable (timed out)" in text


def test_format_nagios_unknown_when_nothing_inspected():
    text, code = format_nagios([], [])
    assert code == NAGIOS_UNKNOWN
    assert "UNKNOWN" in text


def test_format_nagios_overall_is_worst_severity(make_cert):
    results = [
        ("a.example.com", _info(make_cert(days_valid=200)), 0),
        ("b.example.com", _info(make_cert(days_valid=10)), 3),
    ]
    _, code = format_nagios(results)
    assert code == NAGIOS_WARNING


def test_format_prometheus_exposes_metrics(make_cert):
    info = _info(make_cert(days_valid=42))
    results = [("example.com", info, 0)]
    text = format_prometheus(results)
    assert "# TYPE certinspect_cert_expiry_days gauge" in text
    assert 'certinspect_up{target="example.com"} 1' in text
    assert 'certinspect_cert_valid{target="example.com"} 1' in text
    days = info["days_to_expire"]
    assert f'certinspect_cert_expiry_days{{target="example.com"}} {days}' in text


def test_format_prometheus_marks_expired_as_invalid(make_cert):
    results = [("example.com", _info(make_cert(days_valid=-5, days_ago_start=365)), 4)]
    text = format_prometheus(results)
    assert 'certinspect_cert_valid{target="example.com"} 0' in text


def test_format_prometheus_marks_unreachable_target_down():
    text = format_prometheus([], [("bad.example.com", "timed out")])
    assert 'certinspect_up{target="bad.example.com"} 0' in text


def test_format_prometheus_escapes_label(make_cert):
    results = [('weird"name', _info(make_cert(days_valid=42)), 0)]
    text = format_prometheus(results)
    assert 'certinspect_up{target="weird\\"name"} 1' in text


def test_format_prometheus_output_parses_with_prometheus_client(make_cert):
    """The output is valid exposition format per the official parser."""
    parser = pytest.importorskip("prometheus_client.parser")

    info = _info(make_cert(san=["example.com"], days_valid=42))
    text = format_prometheus(
        [("example.com", info, 0)],
        [("down.example.com", "timed out")],
    )

    families = {f.name: f for f in parser.text_string_to_metric_families(text)}
    assert set(families) == {
        "certinspect_up",
        "certinspect_cert_expiry_days",
        "certinspect_cert_valid",
    }

    up = {s.labels["target"]: s.value for s in families["certinspect_up"].samples}
    assert up == {"example.com": 1.0, "down.example.com": 0.0}

    expiry = families["certinspect_cert_expiry_days"].samples
    assert len(expiry) == 1
    assert expiry[0].labels == {"target": "example.com"}
    assert expiry[0].value == float(info["days_to_expire"])
