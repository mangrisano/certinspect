"""Tests for the formatter module: format_human and format_json."""

import json

from certinspect.formatter import format_human, format_json
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
