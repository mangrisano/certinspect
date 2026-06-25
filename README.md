# certinspect

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

# Save the fetched certificate as PEM
certinspect example.com --export ./fetched.pem

# Print the version
certinspect --version
```

## Options

| Option          | Description                                                  |
| --------------- | ------------------------------------------------------------ |
| `target...`     | One or more domains to inspect. Omit when using `--file`.    |
| `--file PATH`   | Inspect a local certificate (PEM or DER) instead of a host.  |
| `--port N`      | TCP port to connect to (default: 443).                       |
| `--timeout N`   | Connection timeout in seconds (default: 5).                  |
| `--json`        | Print the result as JSON instead of human-readable text.     |
| `--quiet`       | Only print certificates that have a problem.                 |
| `--days N`      | Warn if the certificate expires within N days (default: 30). |
| `--export PATH` | Save the inspected certificate as a PEM file at PATH.        |
| `--version`     | Print the version and exit.                                  |

## Exit codes

Designed for automation (cron, CI, monitoring scripts). In batch mode the
worst code across all targets is returned.

| Code | Meaning                                 |
| ---- | --------------------------------------- |
| 0    | Valid certificate                       |
| 1    | Runtime error (network, file, parse)    |
| 2    | Command-line usage error                |
| 3    | Expiring within the `--days` threshold  |
| 4    | Expired or with invalid dates           |
| 5    | Hostname does not match the certificate |

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
