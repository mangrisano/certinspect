"""Tests for the parser module: load_certificate and analyze."""

from datetime import datetime

import pytest

from certinspect.parser import (
    CertificateLoadError,
    analyze,
    certificate_status,
    hostname_matches,
    load_certificate,
    to_pem,
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
