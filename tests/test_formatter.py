"""Tests for the formatter module: format_human and format_json."""

import csv
import io
import json

import pytest

from certinspect.formatter import (
    NAGIOS_CRITICAL,
    NAGIOS_OK,
    NAGIOS_UNKNOWN,
    NAGIOS_WARNING,
    format_csv,
    format_human,
    format_json,
    format_nagios,
    format_prometheus,
    format_summary,
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


def test_format_human_expected_san_ok(make_cert):
    info = _info(make_cert(san=["example.com"]))
    info["expected_san_missing"] = []
    text = format_human(info)
    assert "Expected SAN:" in text
    assert "ok" in text
    assert "does not cover" not in text


def test_format_human_expected_san_missing_warns(make_cert):
    info = _info(make_cert(san=["example.com"]))
    info["expected_san_missing"] = ["api.example.com"]
    text = format_human(info)
    assert "Expected SAN:" in text
    assert "MISSING" in text
    assert "WARNING: SAN does not cover 'api.example.com'" in text


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


def _parse_csv(text):
    return list(csv.DictReader(io.StringIO(text)))


def test_format_csv_has_header_and_one_row_per_target(make_cert):
    results = [
        ("a.example.com", _info(make_cert(san=["a.example.com"])), 0),
        ("b.example.com", _info(make_cert(san=["b.example.com"])), 0),
    ]
    rows = _parse_csv(format_csv(results))
    assert [r["target"] for r in rows] == ["a.example.com", "b.example.com"]


def test_format_csv_includes_expected_columns(make_cert):
    info = _info(make_cert(san=["example.com"], days_valid=200))
    rows = _parse_csv(format_csv([("example.com", info, 0)]))
    row = rows[0]
    assert row["status"] == "VALID"
    assert row["days_to_expire"] == str(info["days_to_expire"])
    assert row["common_name"] == "example.com"
    assert row["valid_until"] == str(info["not_valid_after"])


def test_format_csv_columns_have_no_embedded_commas(make_cert):
    # The lean columns must be comma-free so the file opens cleanly in a
    # spreadsheet without any quoting.
    info = _info(make_cert(san=["example.com"], days_valid=200))
    text = format_csv([("example.com", info, 0)])
    assert '"' not in text


def test_format_csv_issuer_is_common_name_only(make_cert):
    info = _info(make_cert(san=["example.com"], issuer_name="Example Root CA"))
    rows = _parse_csv(format_csv([("example.com", info, 0)]))
    assert rows[0]["issuer"] == "Example Root CA"


def test_format_csv_custom_delimiter(make_cert):
    info = _info(make_cert(san=["example.com"], days_valid=200))
    text = format_csv([("example.com", info, 0)], delimiter=";")
    rows = list(csv.DictReader(io.StringIO(text), delimiter=";"))
    assert rows[0]["target"] == "example.com"
    assert rows[0]["status"] == "VALID"


def test_format_csv_status_reflects_expiry(make_cert):
    info = _info(make_cert(days_valid=10))
    rows = _parse_csv(format_csv([("example.com", info, 3)], warn_days=30))
    assert rows[0]["status"] == "EXPIRING"


def test_format_csv_empty_results_has_header_only(make_cert):
    text = format_csv([])
    rows = _parse_csv(text)
    assert rows == []
    assert text.splitlines()[0].startswith("target,")


def test_format_csv_empty_target_for_file_source(der_cert):
    rows = _parse_csv(format_csv([(None, _info(der_cert), 0)]))
    assert rows[0]["target"] == ""


def test_format_summary_counts_by_code(make_cert):
    info = _info(make_cert(san=["example.com"]))
    results = [
        ("a.com", info, 0),
        ("b.com", info, 0),
        ("c.com", info, 3),
        ("d.com", info, 4),
    ]
    line = format_summary(results)
    assert line == "summary: 2 valid · 1 expiring · 1 expired (4 targets)"


def test_format_summary_includes_errors_and_problem_codes(make_cert):
    info = _info(make_cert(san=["example.com"]))
    results = [("a.com", info, 0), ("b.com", info, 5)]
    line = format_summary(results, errors=[("x.com", "boom")])
    assert "1 mismatch" in line
    assert "1 error" in line
    assert line.endswith("(3 targets)")


def test_format_summary_hides_zero_problem_categories(make_cert):
    info = _info(make_cert(san=["example.com"]))
    line = format_summary([("a.com", info, 0)])
    assert "mismatch" not in line
    assert "untrusted" not in line
    assert line == "summary: 1 valid · 0 expiring · 0 expired (1 target)"


def test_format_summary_splits_critical_from_expired(make_cert):
    soon = _info(make_cert(san=["soon.com"], days_valid=3))
    expired = _info(make_cert(san=["x.com"], days_valid=-5, days_ago_start=365))
    # Both carry exit code 4; critical_days separates them in the tally.
    results = [("soon.com", soon, 4), ("x.com", expired, 4)]
    line = format_summary(results, warn_days=30, critical_days=7)
    assert "1 critical" in line
    assert "1 expired" in line


def test_format_summary_shows_critical_zero_when_threshold_set(make_cert):
    info = _info(make_cert(san=["a.com"], days_valid=200))
    line = format_summary([("a.com", info, 0)], critical_days=7)
    assert "0 critical" in line
