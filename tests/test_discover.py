"""Tests for Certificate Transparency discovery (no network access)."""

import json

import pytest

from certinspect.discover import (
    DiscoveredCert,
    _extract_names,
    discover_certificates,
    discover_hostnames,
)


def test_extract_names_keeps_domain_and_subdomains():
    records = [
        {"common_name": "example.com", "name_value": "example.com\nwww.example.com"},
        {"common_name": "api.example.com", "name_value": "api.example.com"},
    ]
    assert _extract_names(records, "example.com") == {
        "example.com",
        "www.example.com",
        "api.example.com",
    }


def test_extract_names_drops_wildcards_and_foreign_names():
    records = [
        {"common_name": "*.example.com", "name_value": "*.example.com\nok.example.com"},
        {"common_name": "evil.com", "name_value": "evil.com"},
        {"common_name": "", "name_value": "notexample.com"},
    ]
    assert _extract_names(records, "example.com") == {"ok.example.com"}


def test_extract_names_is_case_insensitive_and_dedups():
    records = [{"common_name": "WWW.Example.COM", "name_value": "www.example.com."}]
    assert _extract_names(records, "Example.com") == {"www.example.com"}


def test_discover_hostnames_parses_and_sorts(monkeypatch):
    payload = json.dumps(
        [
            {"common_name": "b.example.com", "name_value": "b.example.com"},
            {
                "common_name": "a.example.com",
                "name_value": "a.example.com\n*.example.com",
            },
        ]
    ).encode()
    monkeypatch.setattr("certinspect.discover._http", lambda url, *, timeout: payload)
    assert discover_hostnames("example.com", 5.0) == ["a.example.com", "b.example.com"]


def test_discover_hostnames_rejects_non_json(monkeypatch):
    monkeypatch.setattr("certinspect.discover._http", lambda url, *, timeout: b"nope")
    with pytest.raises(ValueError, match="could not parse"):
        discover_hostnames("example.com", 5.0)


def test_discover_hostnames_rejects_non_array(monkeypatch):
    monkeypatch.setattr("certinspect.discover._http", lambda url, *, timeout: b"{}")
    with pytest.raises(ValueError, match="expected a JSON array"):
        discover_hostnames("example.com", 5.0)


def test_extract_names_can_keep_wildcards():
    records = [{"common_name": "*.example.com", "name_value": "*.example.com"}]
    assert _extract_names(records, "example.com") == set()
    assert _extract_names(records, "example.com", keep_wildcards=True) == {
        "*.example.com"
    }


def test_discover_certificates_dedups_by_serial_and_keeps_metadata(monkeypatch):
    record = {
        "common_name": "example.com",
        "name_value": "example.com\nwww.example.com",
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "not_before": "2024-01-01T00:00:00",
        "not_after": "2024-04-01T00:00:00",
        "serial_number": "abc",
    }
    # The same serial appears twice (precert + final cert) and must collapse.
    payload = json.dumps([record, dict(record)]).encode()
    monkeypatch.setattr("certinspect.discover._http", lambda url, *, timeout: payload)
    assert discover_certificates("example.com", 5.0) == [
        DiscoveredCert(
            hostnames=("example.com", "www.example.com"),
            issuer="C=US, O=Let's Encrypt, CN=R3",
            not_before="2024-01-01T00:00:00",
            not_after="2024-04-01T00:00:00",
        )
    ]


def test_discover_certificates_sorts_by_expiry_and_keeps_wildcards(monkeypatch):
    payload = json.dumps(
        [
            {
                "common_name": "b.example.com",
                "name_value": "b.example.com",
                "issuer_name": "CN=Late CA",
                "not_after": "2025-12-01T00:00:00",
                "serial_number": "2",
            },
            {
                "common_name": "*.example.com",
                "name_value": "*.example.com",
                "issuer_name": "CN=Early CA",
                "not_after": "2025-01-01T00:00:00",
                "serial_number": "1",
            },
        ]
    ).encode()
    monkeypatch.setattr("certinspect.discover._http", lambda url, *, timeout: payload)
    certs = discover_certificates("example.com", 5.0)
    assert [cert.hostnames for cert in certs] == [
        ("*.example.com",),
        ("b.example.com",),
    ]
