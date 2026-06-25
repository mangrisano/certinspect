"""Tests for the network helpers that do not require a live server."""

import pytest

from certinspect.fetch import check_revocation
from certinspect.parser import load_certificate


def test_check_revocation_unavailable_without_aia(make_cert):
    cert = load_certificate(make_cert())
    status, detail = check_revocation(cert)
    assert status == "UNAVAILABLE"
    assert "AIA" in detail


def test_check_revocation_accepts_explicit_issuer(make_cert):
    cert = load_certificate(make_cert())
    # Passing an issuer must not require a network download; with no OCSP
    # responder in the certificate the result is still UNAVAILABLE.
    status, _ = check_revocation(cert, issuer=cert)
    assert status == "UNAVAILABLE"


def test_http_rejects_unsupported_scheme():
    from certinspect.fetch import _http

    with pytest.raises(ValueError, match="unsupported URL scheme"):
        _http("ftp://example.com/cert", timeout=1.0)
