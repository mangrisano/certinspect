# certinspect

[![CI](https://github.com/mangrisano/certinspect/actions/workflows/ci.yml/badge.svg)](https://github.com/mangrisano/certinspect/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/certinspect.svg)](https://pypi.org/project/certinspect/)
[![Python](https://img.shields.io/pypi/pyversions/certinspect.svg)](https://pypi.org/project/certinspect/)

Command-line TLS certificate inspector.

Given one or more domains (or a `.pem`/`.der` file), it reports validity,
days to expiry, total validity period, subject, issuer, SAN, signature
algorithm, key size, SHA-256 fingerprint, CA flag, self-signed flag, key
usage and extended key usage, weak-crypto warnings, the negotiated TLS
version and cipher, and whether the hostname matches the certificate.

## Requirements

- Python >= 3.10

## Installation

```bash
pip install certinspect
```

### From source (development)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
# Inspect a host
certinspect example.com

# Multiple hosts at once (batch mode)
certinspect example.com github.com api.example.com

# Custom port
certinspect example.com --port 8443

# Custom connection timeout in seconds (default: 5)
certinspect example.com --timeout 10

# JSON output (always a list of objects)
certinspect example.com --json

# Inspect a local certificate
certinspect --file ./certificate.pem

# Custom expiry warning threshold (default: 30 days)
certinspect example.com --days 14

# Only print certificates that have a problem
certinspect example.com github.com --quiet

# Verify the certificate chain against the system trust store
certinspect example.com --verify

# Show the certificate chain presented by the server
certinspect example.com --chain

# Fail (exit 7) unless the fingerprint matches the expected pin
certinspect example.com --pin AA:BB:CC:...

# Read targets from a file (or '-' for stdin)
certinspect --input hosts.txt
cat hosts.txt | certinspect --input -

# Save the fetched certificate as PEM
certinspect example.com --export ./fetched.pem

# Print the version
certinspect --version
```

## Example

```console
$ certinspect pypi.org --verify
=== pypi.org ===
Subject:        CN=pypi.org
Status:         VALID

Issuer:         CN=GlobalSign Atlas R3 DV TLS CA 2025 Q4,O=GlobalSign nv-sa,C=BE
Valid from:     2025-12-28 04:33:08+00:00
Valid until:    2027-01-29 04:33:07+00:00
Days to expiry: 217
Total validity: 396 days

Serial number:  1587345912129534630556007389588586994
Signature:      sha256WithRSAEncryption
Key size:       2048 bit
Fingerprint:    15:58:1C:41:02:3F:07:89:85:31:4E:7D:4C:4F:8A:CA:BF:05:C7:F6:...
CA:             False
Self-Signed:    False
TLS version:    TLSv1.3
Cipher:         TLS_AES_128_GCM_SHA256
Key usage:      digital_signature, key_encipherment
Ext. key usage: serverAuth, clientAuth
Hostname match: True
Chain trusted:  True
Revocation:     GOOD

SAN:
  - pypi.org
  - *.pypi.org
  - www.pypi.org
  - donate.pypi.org
```

With `--verify`, certinspect opens a fully verified TLS handshake (chain +
hostname against the Python/OpenSSL trust store) and, when the certificate
advertises an OCSP responder, queries it for the revocation status. OCSP is
soft-fail: an unreachable responder reports `UNAVAILABLE` and does not change
the exit code, while a `REVOKED` status fails with exit code 6. Revocation is
not checked via CRLs.

## Options

| Option          | Description                                                                 |
| --------------- | --------------------------------------------------------------------------- |
| `target...`     | One or more domains to inspect. Omit when using `--file`.                   |
| `--file PATH`   | Inspect a local certificate (PEM or DER) instead of a host.                 |
| `--port N`      | TCP port to connect to (default: 443).                                      |
| `--timeout N`   | Connection timeout in seconds (default: 5).                                 |
| `--json`        | Print the result as JSON instead of human-readable text.                    |
| `--quiet`       | Only print certificates that have a problem.                                |
| `--verify`      | Verify the chain + OCSP revocation, system trust store (hosts only).        |
| `--chain`       | Show the certificate chain presented by the server.                         |
| `--pin SHA256`  | Fail (exit 7) unless the SHA-256 fingerprint matches (colons/case ignored). |
| `--input PATH`  | Read extra targets from a file, one per line ('-' for stdin).               |
| `--days N`      | Warn if the certificate expires within N days (default: 30).                |
| `--export PATH` | Save the inspected certificate as a PEM file at PATH.                       |
| `--version`     | Print the version and exit.                                                 |

## Exit codes

Designed for automation (cron, CI, monitoring scripts). In batch mode the
worst code across all targets is returned.

| Code | Meaning                                   |
| ---- | ----------------------------------------- |
| 0    | Valid certificate                         |
| 1    | Runtime error (network, file, parse)      |
| 2    | Command-line usage error                  |
| 3    | Expiring within the `--days` threshold    |
| 4    | Expired or with invalid dates             |
| 5    | Hostname does not match the certificate   |
| 6    | Chain not trusted or revoked (`--verify`) |
| 7    | Fingerprint does not match `--pin`        |

Example in a script:

```bash
certinspect yoursite.com --days 21
case $? in
  0) ;;                                        # all good
  3) echo "Expiring" | mail -s "Warning" you@mail.com ;;
  4) echo "Expired"  | mail -s "Urgent"  you@mail.com ;;
  5) echo "Bad host" | mail -s "Urgent"  you@mail.com ;;
  *) echo "Check failed" ;;
esac
```

## Development

```bash
# Tests
pytest

# Lint and formatting (Ruff)
ruff check src tests
ruff format src tests
```

## License

MIT — see [LICENSE](LICENSE).
