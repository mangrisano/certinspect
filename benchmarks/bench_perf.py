"""Performance benchmarks for certinspect's offline (network-free) hot paths.

Run in CI by the Performance workflow via pytest-benchmark. These are not part
of the normal test suite (the ``bench_*`` filename keeps them out of default
collection); they exercise certificate parsing, analysis and JSON rendering
without any network access.
"""

from pathlib import Path

from certinspect.formatter import format_json
from certinspect.parser import analyze, load_certificate

_CERT_BYTES = (Path(__file__).resolve().parents[1] / "sample-cert.pem").read_bytes()


def test_load_certificate(benchmark):
    benchmark(load_certificate, _CERT_BYTES)


def test_analyze(benchmark):
    cert = load_certificate(_CERT_BYTES)
    benchmark(analyze, cert)


def test_format_json(benchmark):
    data = analyze(load_certificate(_CERT_BYTES))
    benchmark(format_json, data)
