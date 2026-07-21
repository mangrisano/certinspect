"""Tests for the parser module: load_certificate and analyze."""

from datetime import date, datetime

import pytest

from certinspect.parser import (
    CertificateLoadError,
    analyze,
    cab_forum_max_validity,
    certificate_status,
    chain_expiry_warnings,
    chain_summary,
    hostname_matches,
    load_certificate,
    missing_san_names,
    pin_matches,
    policy_violations,
    to_pem,
    tls_version_rank,
)


def test_load_der_certificate(der_cert):
    cert = load_certificate(der_cert)
    assert cert.subject.rfc4514_string() == "CN=example.com"


def test_load_pem_certificate(pem_cert):
    cert = load_certificate(pem_cert)
    assert cert.subject.rfc4514_string() == "CN=example.com"


def test_load_empty_raises_certificate_load_error():
    with pytest.raises(CertificateLoadError):
        load_certificate(b"")


def test_load_garbage_raises_value_error():
    with pytest.raises(ValueError):
        load_certificate(b"not a certificate")


def test_certificate_load_error_is_value_error():
    # The custom error must remain catchable as a plain ValueError.
    assert issubclass(CertificateLoadError, ValueError)


def test_analyze_basic_fields(der_cert):
    info = analyze(load_certificate(der_cert))
    assert info["subject"] == "CN=example.com"
    assert info["issuer"] == "CN=example.com"
    assert info["signature_algorithm"] == "sha256WithRSAEncryption"
    assert info["key_size"] == 2048
    assert isinstance(info["serial_number"], int)


def test_analyze_dates_are_timezone_aware(der_cert):
    info = analyze(load_certificate(der_cert))
    for field in ("not_valid_before", "not_valid_after"):
        value = info[field]
        assert isinstance(value, datetime)
        assert value.tzinfo is not None


def test_analyze_days_to_expire_positive(make_cert):
    info = analyze(load_certificate(make_cert(days_valid=30)))
    # ~30 days minus a moment of elapsed time.
    assert 28 <= info["days_to_expire"] <= 30


def test_analyze_days_to_expire_negative_for_expired(make_cert):
    expired = make_cert(days_valid=-5, days_ago_start=365)
    info = analyze(load_certificate(expired))
    assert info["days_to_expire"] < 0


def test_analyze_san_present(make_cert):
    info = analyze(load_certificate(make_cert(san=["a.example.com", "b.example.com"])))
    assert info["san"] == ["a.example.com", "b.example.com"]


def test_analyze_san_absent_returns_empty_list(make_cert):
    info = analyze(load_certificate(make_cert(san=None)))
    assert info["san"] == []


def test_analyze_san_includes_ip_addresses(make_cert):
    info = analyze(
        load_certificate(
            make_cert(san=["example.com"], san_ips=["10.0.0.5", "2001:db8::1"])
        )
    )
    assert info["san"] == ["example.com", "10.0.0.5", "2001:db8::1"]


def test_analyze_san_ip_only(make_cert):
    info = analyze(load_certificate(make_cert(san=None, san_ips=["192.0.2.10"])))
    assert info["san"] == ["192.0.2.10"]


def test_missing_san_names_matches_ip(make_cert):
    info = analyze(
        load_certificate(make_cert(san=["example.com"], san_ips=["10.0.0.5"]))
    )
    assert missing_san_names(info, ["10.0.0.5"]) == []
    assert missing_san_names(info, ["10.0.0.6"]) == ["10.0.0.6"]


def test_hostname_matches_ip(make_cert):
    info = analyze(load_certificate(make_cert(san=None, san_ips=["10.0.0.5"])))
    assert hostname_matches(info, "10.0.0.5") is True
    assert hostname_matches(info, "10.0.0.6") is False


def test_analyze_fingerprint_format(der_cert):
    info = analyze(load_certificate(der_cert))
    fp = info["fingerprint_sha256"]
    assert isinstance(fp, str)
    parts = fp.split(":")
    # SHA-256 = 32 bytes -> 32 colon-separated hex pairs.
    assert len(parts) == 32
    assert all(len(p) == 2 for p in parts)
    assert fp == fp.upper()


def test_analyze_keys_match_expected_set(der_cert):
    info = analyze(load_certificate(der_cert))
    expected = {
        "subject",
        "issuer",
        "not_valid_before",
        "not_valid_after",
        "serial_number",
        "signature_algorithm",
        "days_to_expire",
        "validity_days",
        "key_size",
        "san",
        "fingerprint_sha256",
        "is_ca",
        "self_signed",
        "key_usage",
        "extended_key_usage",
        "sct_count",
        "must_staple",
        "weak",
    }
    assert set(info) == expected


def test_analyze_self_signed_true(make_cert):
    info = analyze(load_certificate(make_cert()))
    assert info["self_signed"] is True


def test_analyze_self_signed_false(make_cert):
    info = analyze(load_certificate(make_cert(issuer_name="Some Real CA")))
    assert info["self_signed"] is False


def test_analyze_weak_empty_for_strong_cert(make_cert):
    info = analyze(load_certificate(make_cert()))
    assert info["weak"] == []


def test_analyze_weak_flags_small_key(make_cert):
    info = analyze(load_certificate(make_cert(key_size=1024)))
    assert any("key" in reason.lower() for reason in info["weak"])


def test_analyze_weak_empty_for_ec_p256(make_cert):
    from cryptography.hazmat.primitives.asymmetric import ec

    info = analyze(load_certificate(make_cert(ec_curve=ec.SECP256R1())))
    assert info["weak"] == []


def test_analyze_weak_flags_sha1_signature(make_cert):
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives import hashes

    try:
        cert_bytes = make_cert(sig_hash=hashes.SHA1())
    except UnsupportedAlgorithm:
        pytest.skip("SHA-1 signatures are not supported by this OpenSSL build")
    info = analyze(load_certificate(cert_bytes))
    assert any("signature" in reason.lower() for reason in info["weak"])


def test_analyze_validity_days(make_cert):
    info = analyze(load_certificate(make_cert(days_valid=90, days_ago_start=10)))
    # 10 days in the past + 90 days in the future = 100 days total.
    assert info["validity_days"] == 100


def test_analyze_key_usage_empty_when_absent(make_cert):
    info = analyze(load_certificate(make_cert()))
    assert info["key_usage"] == []
    assert info["extended_key_usage"] == []


def test_analyze_key_usage_lists_enabled_flags(make_cert):
    from cryptography import x509

    ku = x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=True,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )
    info = analyze(load_certificate(make_cert(key_usage=ku)))
    assert info["key_usage"] == ["digital_signature", "key_encipherment"]


def test_analyze_extended_key_usage_names(make_cert):
    from cryptography.x509.oid import ExtendedKeyUsageOID

    info = analyze(
        load_certificate(
            make_cert(
                extended_key_usage=[
                    ExtendedKeyUsageOID.SERVER_AUTH,
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                ]
            )
        )
    )
    assert info["extended_key_usage"] == ["serverAuth", "clientAuth"]


def _info_with_san(make_cert, san):
    return analyze(load_certificate(make_cert(san=san)))


def test_hostname_matches_exact(make_cert):
    info = _info_with_san(make_cert, ["example.com", "www.example.com"])
    assert hostname_matches(info, "example.com") is True
    assert hostname_matches(info, "www.example.com") is True


def test_hostname_matches_is_case_insensitive(make_cert):
    info = _info_with_san(make_cert, ["example.com"])
    assert hostname_matches(info, "Example.COM") is True


def test_hostname_matches_wildcard_single_label(make_cert):
    info = _info_with_san(make_cert, ["*.example.com"])
    assert hostname_matches(info, "www.example.com") is True


def test_hostname_wildcard_does_not_match_bare_domain(make_cert):
    info = _info_with_san(make_cert, ["*.example.com"])
    assert hostname_matches(info, "example.com") is False


def test_hostname_wildcard_does_not_match_multiple_labels(make_cert):
    info = _info_with_san(make_cert, ["*.example.com"])
    assert hostname_matches(info, "a.b.example.com") is False


def test_hostname_no_match(make_cert):
    info = _info_with_san(make_cert, ["example.com"])
    assert hostname_matches(info, "evil.com") is False


def test_hostname_matches_empty_san(make_cert):
    info = _info_with_san(make_cert, None)
    assert hostname_matches(info, "example.com") is False


def test_missing_san_names_all_covered_returns_empty(make_cert):
    info = _info_with_san(make_cert, ["example.com", "www.example.com"])
    assert missing_san_names(info, ["example.com", "www.example.com"]) == []


def test_missing_san_names_reports_uncovered(make_cert):
    info = _info_with_san(make_cert, ["example.com"])
    assert missing_san_names(info, ["example.com", "api.example.com"]) == [
        "api.example.com"
    ]


def test_missing_san_names_honors_wildcards(make_cert):
    info = _info_with_san(make_cert, ["*.example.com"])
    assert missing_san_names(info, ["api.example.com", "web.example.com"]) == []


def test_missing_san_names_preserves_input_order(make_cert):
    info = _info_with_san(make_cert, ["b.example.com"])
    assert missing_san_names(
        info, ["a.example.com", "b.example.com", "c.example.com"]
    ) == [
        "a.example.com",
        "c.example.com",
    ]


def test_to_pem_round_trips(der_cert):
    pem = to_pem(load_certificate(der_cert))
    assert pem.startswith(b"-----BEGIN CERTIFICATE-----")
    # The PEM output must load back into an equivalent certificate.
    reloaded = load_certificate(pem)
    assert reloaded.subject.rfc4514_string() == "CN=example.com"


def test_analyze_is_ca_false_for_leaf(make_cert):
    info = analyze(load_certificate(make_cert(ca=False)))
    assert info["is_ca"] is False


def test_analyze_is_ca_true_for_ca(make_cert):
    info = analyze(load_certificate(make_cert(ca=True)))
    assert info["is_ca"] is True


def test_status_valid(make_cert):
    info = analyze(load_certificate(make_cert(days_valid=90)))
    assert certificate_status(info, warn_days=30) == "VALID"


def test_status_expiring(make_cert):
    info = analyze(load_certificate(make_cert(days_valid=10)))
    assert certificate_status(info, warn_days=30) == "EXPIRING"


def test_status_expired(make_cert):
    info = analyze(load_certificate(make_cert(days_valid=-5, days_ago_start=365)))
    assert certificate_status(info, warn_days=30) == "EXPIRED"


def test_status_threshold_is_configurable(make_cert):
    info = analyze(load_certificate(make_cert(days_valid=10)))
    assert certificate_status(info, warn_days=5) == "VALID"


def test_status_critical_within_critical_days(make_cert):
    info = analyze(load_certificate(make_cert(days_valid=3)))
    # Inside the critical window -> CRITICAL, not just EXPIRING.
    assert certificate_status(info, warn_days=30, critical_days=7) == "CRITICAL"


def test_status_expiring_between_critical_and_warn(make_cert):
    info = analyze(load_certificate(make_cert(days_valid=20)))
    # Past the critical window but inside the warning window -> EXPIRING.
    assert certificate_status(info, warn_days=30, critical_days=7) == "EXPIRING"


def test_status_critical_ignored_without_threshold(make_cert):
    info = analyze(load_certificate(make_cert(days_valid=3)))
    assert certificate_status(info, warn_days=30) == "EXPIRING"


def test_status_not_yet_valid(make_cert):
    # Validity starts 5 days in the future -> the cert cannot be used yet.
    info = analyze(load_certificate(make_cert(days_ago_start=-5, days_valid=90)))
    assert certificate_status(info, warn_days=30) == "NOT YET VALID"


def test_analyze_sct_count_absent_is_zero(make_cert):
    # A freshly built certificate carries no embedded SCTs.
    info = analyze(load_certificate(make_cert()))
    assert info["sct_count"] == 0


def test_policy_require_sct_fails_without_scts(make_cert):
    info = analyze(load_certificate(make_cert()))
    violations = policy_violations(info, require_sct=True)
    assert len(violations) == 1
    assert "Certificate Transparency" in violations[0]


def test_analyze_must_staple_absent_is_false(make_cert):
    info = analyze(load_certificate(make_cert()))
    assert info["must_staple"] is False


def test_analyze_must_staple_present_is_true(make_cert):
    info = analyze(load_certificate(make_cert(must_staple=True)))
    assert info["must_staple"] is True


def test_policy_require_must_staple_fails_when_absent(make_cert):
    info = analyze(load_certificate(make_cert()))
    violations = policy_violations(info, require_must_staple=True)
    assert violations == ["missing OCSP Must-Staple extension"]


def test_policy_require_must_staple_passes_when_present(make_cert):
    info = analyze(load_certificate(make_cert(must_staple=True)))
    assert policy_violations(info, require_must_staple=True) == []


def test_policy_require_sct_off_by_default(make_cert):
    info = analyze(load_certificate(make_cert()))
    assert policy_violations(info) == []


def test_tls_version_rank_orders_newest_highest():
    assert tls_version_rank("TLSv1.3") > tls_version_rank("TLSv1.2")
    assert tls_version_rank("TLSv1.2") > tls_version_rank("TLSv1")
    assert tls_version_rank("TLSv1.0") == tls_version_rank("TLSv1")
    assert tls_version_rank("bogus") is None


def test_policy_min_tls_version_fails_when_below(make_cert):
    info = analyze(load_certificate(make_cert()))
    info["tls_version"] = "TLSv1.1"
    violations = policy_violations(info, min_tls_version="TLSv1.2")
    assert violations == ["TLS version TLSv1.1 is below the required TLSv1.2"]


def test_policy_min_tls_version_passes_when_at_or_above(make_cert):
    info = analyze(load_certificate(make_cert()))
    info["tls_version"] = "TLSv1.3"
    assert policy_violations(info, min_tls_version="TLSv1.2") == []


def test_policy_min_tls_version_skipped_without_handshake(make_cert):
    # A --file target has no negotiated TLS version, so the check is a no-op.
    info = analyze(load_certificate(make_cert()))
    assert policy_violations(info, min_tls_version="TLSv1.3") == []


def test_pin_matches_exact(make_cert):
    info = analyze(load_certificate(make_cert()))
    assert pin_matches(info, info["fingerprint_sha256"]) is True


def test_pin_matches_ignores_colons_and_case(make_cert):
    info = analyze(load_certificate(make_cert()))
    pin = info["fingerprint_sha256"].replace(":", "").lower()
    assert pin_matches(info, pin) is True


def test_pin_does_not_match_other(make_cert):
    info = analyze(load_certificate(make_cert()))
    assert pin_matches(info, "00:11:22") is False


def test_chain_summary_fields(make_cert):
    summary = chain_summary(load_certificate(make_cert(ca=True)))
    assert summary["subject"] == "CN=example.com"
    assert summary["is_ca"] is True
    assert "not_valid_after" in summary
    assert "serial_number" in summary


def test_chain_expiry_warnings_empty_for_healthy_chain(make_cert):
    leaf = load_certificate(make_cert())
    inter = load_certificate(make_cert(common_name="Intermediate CA", ca=True))
    assert chain_expiry_warnings([leaf, inter]) == []


def test_chain_expiry_warnings_flags_expired_intermediate(make_cert):
    leaf = load_certificate(make_cert())
    inter = load_certificate(
        make_cert(common_name="Old CA", ca=True, days_valid=-5, days_ago_start=400)
    )
    warnings = chain_expiry_warnings([leaf, inter])
    assert len(warnings) == 1
    assert "Old CA" in warnings[0]
    assert "expired" in warnings[0]


def test_chain_expiry_warnings_flags_soon_to_expire_intermediate(make_cert):
    leaf = load_certificate(make_cert())
    inter = load_certificate(
        make_cert(common_name="Expiring CA", ca=True, days_valid=10)
    )
    warnings = chain_expiry_warnings([leaf, inter], warn_days=30)
    assert len(warnings) == 1
    assert "Expiring CA" in warnings[0]
    assert "expires in" in warnings[0]


def test_chain_expiry_warnings_ignores_leaf(make_cert):
    # An expired leaf at index 0 must not produce a chain warning; only the
    # intermediates/roots beyond it are inspected.
    leaf = load_certificate(make_cert(days_valid=-5, days_ago_start=400))
    inter = load_certificate(make_cert(common_name="Good CA", ca=True))
    assert chain_expiry_warnings([leaf, inter]) == []


def test_chain_expiry_warnings_empty_for_leaf_only(make_cert):
    assert chain_expiry_warnings([load_certificate(make_cert())]) == []


def test_policy_violations_empty_when_no_check_enabled(make_cert):
    info = analyze(load_certificate(make_cert(key_size=1024)))
    # No policy argument set -> nothing is enforced even for a weak cert.
    assert policy_violations(info) == []


def test_policy_violations_not_after_max_flags_long_validity(make_cert):
    info = analyze(load_certificate(make_cert(days_valid=400)))
    violations = policy_violations(info, not_after_max=398)
    assert len(violations) == 1
    assert "exceeds the 398-day maximum" in violations[0]


def test_policy_violations_not_after_max_ok_within_limit(make_cert):
    info = analyze(load_certificate(make_cert(days_valid=90)))
    assert policy_violations(info, not_after_max=398) == []


def test_policy_violations_min_key_size_flags_small_key(make_cert):
    info = analyze(load_certificate(make_cert(key_size=1024)))
    violations = policy_violations(info, min_key_size=2048)
    assert len(violations) == 1
    assert "below the 2048-bit minimum" in violations[0]


def test_policy_violations_min_key_size_ok_for_large_key(make_cert):
    info = analyze(load_certificate(make_cert(key_size=2048)))
    assert policy_violations(info, min_key_size=2048) == []


def test_policy_violations_fail_weak_promotes_warnings(make_cert):
    info = analyze(load_certificate(make_cert(key_size=1024)))
    violations = policy_violations(info, fail_weak=True)
    # The weak-key warning is promoted verbatim to a violation.
    assert violations == info["weak"]
    assert len(violations) == 1
    assert "1024" in violations[0]


def test_policy_violations_fail_weak_empty_for_strong_cert(make_cert):
    info = analyze(load_certificate(make_cert(key_size=2048)))
    assert policy_violations(info, fail_weak=True) == []


def test_policy_violations_accumulates_all_checks(make_cert):
    info = analyze(load_certificate(make_cert(days_valid=400, key_size=1024)))
    violations = policy_violations(
        info, not_after_max=398, min_key_size=2048, fail_weak=True
    )
    # Long validity + small key (counted once via its own check and once via
    # fail_weak's promotion of the weak-key warning).
    assert len(violations) == 3


@pytest.mark.parametrize(
    ("today", "expected"),
    [
        (date(2025, 1, 1), 398),
        (date(2026, 3, 14), 398),
        (date(2026, 3, 15), 200),
        (date(2027, 3, 14), 200),
        (date(2027, 3, 15), 100),
        (date(2029, 3, 14), 100),
        (date(2029, 3, 15), 47),
        (date(2030, 1, 1), 47),
    ],
)
def test_cab_forum_max_validity_follows_schedule(today, expected):
    assert cab_forum_max_validity(today) == expected


def test_cab_forum_max_validity_defaults_to_today():
    # Without an argument it must return one of the scheduled caps.
    assert cab_forum_max_validity() in {398, 200, 100, 47}
