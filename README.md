<div align="center">

<img src="https://raw.githubusercontent.com/mangrisano/certinspect/main/docs/logo.svg" alt="certinspect" width="440">

[![CI](https://github.com/mangrisano/certinspect/actions/workflows/ci.yml/badge.svg)](https://github.com/mangrisano/certinspect/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/certinspect.svg?cacheSeconds=3600)](https://pypi.org/project/certinspect/)
[![Python](https://img.shields.io/pypi/pyversions/certinspect.svg?cacheSeconds=3600)](https://pypi.org/project/certinspect/)
[![Downloads](https://static.pepy.tech/badge/certinspect)](https://pepy.tech/project/certinspect)
[![License: MIT](https://img.shields.io/pypi/l/certinspect.svg)](LICENSE)

**TLS inspection · Expiry alerts · OCSP/CRL revocation · Chain of trust · Batch & concurrency · STARTTLS · CI-friendly exit codes**

[PyPI](https://pypi.org/project/certinspect/) · [Usage](#usage) · [Use cases](#use-cases) · [Options](#options) · [Recipes](#recipes) · [Exit codes](#exit-codes) · [Changelog](#changelog) · [Issues](https://github.com/mangrisano/certinspect/issues)

</div>

> **Point it at a host. Learn the truth about its TLS certificate.**
> Expiry, chain of trust, OCSP/CRL revocation, weak crypto, hostname match —
> one dependency, one command, and machine-readable output when a robot is
> watching.

`certinspect` is a single-purpose, no-nonsense command-line X.509/TLS inspector
built for humans _and_ cron jobs. It speaks plain text, JSON, CSV, Nagios and
Prometheus, exits with meaningful status codes, runs the whole batch in
parallel, and never phones home. No `openssl s_client | openssl x509 -noout
-text` incantations, no browser clicking through padlock dialogs.

```console
$ certinspect example.com
=== example.com ===
Subject:        CN=example.com
Status:         VALID
Days to expiry: 64
Signature:      ecdsa-with-SHA256
Key size:       256 bit
TLS version:    TLSv1.3
Cipher:         TLS_AES_256_GCM_SHA384
Hostname match: True
...
$ echo $?      # 0 = healthy, 3 = expiring, 4 = expired, 6 = revoked, ...
0
```

## Features

| Area               | What you get                                                                                                                                                                               |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Certificate facts  | Validity & days to expiry, total validity period, subject & issuer, SAN, SHA-256 fingerprint, CA / self-signed flags, key usage & extended key usage                                       |
| Crypto health      | Signature algorithm & key size, weak-crypto warnings, negotiated TLS version & cipher                                                                                                      |
| Trust & revocation | Chain verification + OCSP/CRL revocation against the system trust store (`--verify`), or a private/internal CA bundle (`--cafile`/`--capath`); show the server-presented chain (`--chain`) |
| Chain hygiene      | Warn about expired or soon-to-expire intermediate/root CA certificates in the chain                                                                                                        |
| Identity checks    | Hostname match against the certificate, SHA-256 fingerprint pinning (`--pin`), SAN coverage assertions (`--expect-san`), SNI override for backends behind a load balancer (`--servername`) |
| Batch & speed      | Inspect many hosts at once, in parallel (`--concurrency`), from args or a file (`--input`)                                                                                                 |
| Output formats     | Plain text, JSON (`--json`), CSV (`--csv`), Nagios/Icinga & Prometheus (`--exporter`)                                                                                                      |
| Triage helpers     | Only certs expiring within N days (`--max-days`), sort by host or soonest expiry (`--sort`), one-line tally (`--summary`), tighter CRITICAL threshold (`--critical-days`)                  |
| Protocols          | Direct TLS plus STARTTLS — SMTP, IMAP, POP3, FTP (`--starttls`)                                                                                                                            |
| Automation         | Meaningful exit codes for cron/CI, no telemetry, single runtime dependency                                                                                                                 |

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

# A full URL or host:port works too (scheme and path are ignored)
certinspect https://example.com/login
certinspect example.com:8443

# Multiple hosts at once (batch mode)
certinspect example.com github.com api.example.com

# Inspect many hosts in parallel (output order is preserved)
certinspect example.com github.com api.example.com --concurrency 10

# Custom port
certinspect example.com --port 8443

# Custom connection timeout in seconds (default: 5)
certinspect example.com --timeout 10

# JSON output (always a list of objects)
certinspect example.com --json

# CSV output (one row per target, with a header) for spreadsheets
certinspect example.com github.com --csv

# CSV with a ';' separator (Numbers/Excel in some locales, e.g. Italian)
certinspect example.com github.com --csv --csv-delimiter ';'

# Inspect a local certificate
certinspect --file ./certificate.pem

# Custom expiry warning threshold (default: 30 days)
certinspect example.com --days 14

# Two-tier thresholds: WARNING within 30 days, CRITICAL within 7 (exit 4)
certinspect example.com github.com --days 30 --critical-days 7

# Only print certificates that have a problem
certinspect example.com github.com --quiet

# Only print certificates expiring within N days (expired ones always shown)
certinspect example.com github.com --max-days 30

# Sort the batch output by soonest expiry (or alphabetically by host)
certinspect example.com github.com --sort expiry
certinspect example.com github.com --sort host

# Print a one-line tally (to stderr) after the report
certinspect example.com github.com --summary
# summary: 1 valid · 1 expiring · 0 expired (2 targets)

# Verify the certificate chain against the system trust store
certinspect example.com --verify

# Verify against an internal/private CA instead of the system trust store
certinspect internal.example.lan --verify --cafile ./internal-ca.pem
certinspect internal.example.lan --verify --capath /etc/ssl/internal-certs

# Show the certificate chain presented by the server
certinspect example.com --chain

# Fail (exit 7) unless the fingerprint matches the expected pin
certinspect example.com --pin AA:BB:CC:...

# Reach a specific backend by IP but present the virtual host via SNI
# (the hostname match is checked against --servername)
certinspect 10.0.0.5 --servername api.example.com

# Assert the certificate covers one or more names (exit 8 if any is missing)
certinspect example.com --expect-san www.example.com
certinspect example.com --expect-san example.com --expect-san api.example.com

# Read targets from a file (or '-' for stdin)
certinspect --input hosts.txt
cat hosts.txt | certinspect --input -

# Save the fetched certificate as PEM
certinspect example.com --export ./fetched.pem

# Inspect a certificate behind STARTTLS (smtp, imap, pop3, ftp)
# The protocol's standard port is used unless --port is given
certinspect mail.example.com --starttls smtp
certinspect mail.example.com --starttls imap --port 143

# Monitoring output: a Nagios/Icinga plugin line per target
# (exit code follows the plugin convention: 0=OK, 1=WARNING, 2=CRITICAL)
certinspect example.com --exporter nagios

# Monitoring output: Prometheus textfile-collector metrics
certinspect example.com github.com --exporter prometheus

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
advertises an OCSP responder, queries it for the revocation status. If OCSP is
unavailable, certinspect falls back to the certificate's CRL distribution
points (downloaded over HTTP and verified against the issuer). Both checks are
soft-fail: when neither OCSP nor the CRL gives an answer the status is
`UNAVAILABLE` and the exit code is unchanged, while a `REVOKED` status fails
with exit code 6.

When the responder is down (or the certificate has no OCSP URL at all) the CRL
fallback can still catch a revoked certificate; the `via CRL` note shows which
source answered:

```console
$ certinspect revoked.example.com --verify
=== revoked.example.com ===
Subject:        CN=revoked.example.com
Status:         VALID
...
Chain trusted:  True
Revocation:     REVOKED
WARNING: certificate revoked (revoked at 2026-05-14 09:21:03+00:00 (via CRL))
$ echo $?
6
```

certinspect also inspects the other certificates in the chain (the verified
chain with `--verify`, otherwise the chain presented by the server) and warns
when an intermediate or root CA is already expired or expires within the
`--days` window — an expired intermediate breaks the chain even when the leaf
itself is still valid:

```console
$ certinspect internal.example.lan --verify --cafile ./internal-ca.pem
=== internal.example.lan ===
Subject:        CN=internal.example.lan
Status:         VALID
...
Chain trusted:  True
WARNING: chain certificate 'Example Intermediate CA' expires in 12 days
WARNING: chain certificate 'Example Legacy Root CA' expired 3 days ago
Revocation:     GOOD
```

## Use cases

Real-world scenarios and the command that covers each. Every check is
exit-code driven, so it drops straight into cron, CI or a monitoring stack.

### Keep a whole fleet from expiring

Inspect every host in parallel, show only what expires within 30 days, soonest
first:

```bash
certinspect --input fleet.txt --concurrency 20 --max-days 30 --sort expiry
```

### Fail a CI build before a cert bites you

Non-zero exit (`3` expiring, `4` expired, ...) stops the pipeline:

```bash
certinspect --input fleet.txt --days 14 --quiet || exit 1
```

### Validate a freshly issued cert before deploying it

No network needed — assert the file covers every hostname you serve (exit `8`
if any SAN is missing). Catches an ACME renewal that silently dropped a name:

```bash
certinspect --file ./new-cert.pem \
  --expect-san example.com --expect-san www.example.com --expect-san api.example.com \
  || { echo "cert incomplete, blocking deploy"; exit 1; }
```

### Check one node behind a load balancer / anycast IP

Connect to a specific backend by IP but present the virtual host via SNI; the
hostname match is checked against the name you expect:

```bash
certinspect 10.0.0.5 --servername api.example.com --verify
```

### Inspect services behind an internal / private PKI

Verify the chain against your own CA bundle instead of the system trust store:

```bash
certinspect internal.example.lan --verify --cafile ./internal-ca.pem
```

### Catch a revoked certificate

`--verify` queries OCSP and falls back to the CRL; a revoked leaf fails with
exit `6`:

```bash
certinspect example.com --verify
```

### Spot an expired intermediate before it breaks the chain

An expired intermediate silently breaks trust even when the leaf is still
valid; certinspect warns about it:

```bash
certinspect example.com --verify --days 30
```

### Inspect mail / FTP servers (STARTTLS)

Upgrade a plaintext protocol to TLS before reading the certificate:

```bash
certinspect smtp.example.com --starttls smtp
certinspect imap.example.com --starttls imap
```

### Pin a certificate and alert on unexpected changes

Fail with exit `7` if the fingerprint ever differs from the expected pin:

```bash
certinspect example.com --pin BE:AB:14:CF:39:...
```

### Feed a monitoring stack

Nagios/Icinga plugin lines or Prometheus textfile metrics (see
[Monitoring](#monitoring)):

```bash
certinspect --input fleet.txt --exporter prometheus \
  > /var/lib/node_exporter/textfile/certinspect.prom
```

### Audit a fleet into a spreadsheet

CSV with a locale-friendly separator, one row per host:

```bash
certinspect --input fleet.txt --csv --csv-delimiter ';' > certs.csv
```

### Separate a warning window from a critical one

Two-tier thresholds let alerting distinguish "renew soon" (exit `3`) from
"renew now" (exit `4`) — e.g. page on-call only for the critical window:

```bash
certinspect --input fleet.txt --days 30 --critical-days 7
```

### Send a nightly expiry digest

Only what expires within 30 days, soonest first, with a one-line tally on
stderr, piped to mail:

```bash
certinspect --input fleet.txt --max-days 30 --sort expiry --summary \
  | mail -s "Certs expiring soon" ops@example.com
```

### Pipe results into other tooling

JSON is always a list of objects — feed it to `jq`, a dashboard or a script:

```bash
# Every host sorted by days left
certinspect --input fleet.txt --concurrency 20 --json \
  | jq -r 'sort_by(.days_to_expire)[] | "\(.days_to_expire)d  \(.subject)"'

# Grab just the SHA-256 fingerprint (e.g. to pin it later)
certinspect example.com --json | jq -r '.[0].fingerprint_sha256'
```

### Inspect a service on a non-standard TLS port

Databases, message brokers, admin panels and custom services rarely live on
443:

```bash
certinspect db.example.com --port 5432        # Postgres over TLS
certinspect broker.example.com --port 8883     # MQTT over TLS
```

### Probe slow or high-latency endpoints

Raise the connection timeout for far-away regions or throttled links (default
5s):

```bash
certinspect edge.ap-southeast-2.example.com --timeout 15
```

### Debug the exact chain a server presents

See every certificate the server sends (leaf → intermediates), to diagnose a
missing or mis-ordered intermediate:

```bash
certinspect example.com --chain
```

### Archive the served certificate

Save the fetched leaf as PEM for auditing, diffing or extracting a pin:

```bash
certinspect example.com --export ./example.com.pem
```

## Options

| Option                            | Description                                                                                                                                                      |
| --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `target...`                       | One or more domains, URLs or `host:port` to inspect. Omit when using `--file`.                                                                                   |
| `--file PATH`                     | Inspect a local certificate (PEM or DER) instead of a host.                                                                                                      |
| `--port N`                        | TCP port to connect to (default: 443).                                                                                                                           |
| `--timeout N`                     | Connection timeout in seconds (default: 5).                                                                                                                      |
| `--json`                          | Print the result as JSON instead of human-readable text.                                                                                                         |
| `--csv`                           | Print the results as CSV (one row per target, with a header).                                                                                                    |
| `--csv-delimiter SEP`             | Field separator for `--csv` (default `,`). Use `;` for Numbers/Excel in locales that expect it.                                                                  |
| `--quiet`                         | Only print certificates that have a problem.                                                                                                                     |
| `--verify`                        | Verify the chain + OCSP/CRL revocation, system trust store (hosts only).                                                                                         |
| `--cafile PATH`                   | Verify the chain against this CA bundle (PEM) instead of the system trust store. Requires `--verify`; for internal/private PKI.                                  |
| `--capath DIR`                    | Verify the chain against the hashed CA certificates in this directory (OpenSSL `c_rehash` layout). Requires `--verify`; may be combined with `--cafile`.         |
| `--chain`                         | Show the certificate chain presented by the server.                                                                                                              |
| `--pin SHA256`                    | Fail (exit 7) unless the SHA-256 fingerprint matches (colons/case ignored).                                                                                      |
| `--servername NAME`               | Override the SNI hostname sent in the handshake (hosts only); the hostname match is checked against `NAME`. For reaching a backend by IP behind a load balancer. |
| `--expect-san NAME`               | Assert the certificate's SAN covers `NAME` (wildcards honored); exit 8 if missing. Repeatable; works for host and `--file` targets.                              |
| `--input PATH`                    | Read extra targets from a file, one per line ('-' for stdin).                                                                                                    |
| `--days N`                        | Warn if the certificate expires within N days (default: 30).                                                                                                     |
| `--critical-days N`               | Escalate to CRITICAL (exit code 4) when the certificate expires within N days. Must be `<= --days`; feeds Nagios CRITICAL and the `--summary` `critical` count.  |
| `--max-days N`                    | Only show certificates expiring within N days (expired ones always shown; filters display only).                                                                 |
| `--sort host\|expiry`             | Sort the output by host (alphabetical) or by soonest expiry (display only; does not affect exit code).                                                           |
| `--summary`                       | Print a one-line tally (valid/expiring/expired/errors) to stderr; counts every target before filtering.                                                          |
| `--export PATH`                   | Save the inspected certificate as a PEM file at PATH.                                                                                                            |
| `--starttls {smtp,imap,pop3,ftp}` | Upgrade a plaintext connection to TLS before inspecting (standard port unless `--port` is given).                                                                |
| `--exporter {nagios,prometheus}`  | Emit machine-readable monitoring output (ignores `--quiet`).                                                                                                     |
| `--concurrency N`                 | Inspect up to N hosts in parallel in batch mode (default: 1; order is preserved).                                                                                |
| `--version`                       | Print the version and exit.                                                                                                                                      |

## Options in action

Worked examples with real output for every option. Long values (fingerprints,
issuer names) are trimmed with `...`; `$?` is the process exit code.

### `target` — inspect a host

```console
$ certinspect example.com
=== example.com ===
Subject:        CN=example.com
Status:         VALID

Issuer:         CN=Cloudflare TLS Issuing ECC CA 3,O=SSL Corporation,C=US
Valid from:     2026-05-31 21:39:12+00:00
Valid until:    2026-08-29 21:41:26+00:00
Days to expiry: 64
Total validity: 90 days

Serial number:  35428337808578903465180920265426569102
Signature:      ecdsa-with-SHA256
Key size:       256 bit
Fingerprint:    BE:AB:14:CF:39:67:8F:DA:0E:F1:60:6E:ED:B8:18:C2:...
CA:             False
Self-Signed:    False
TLS version:    TLSv1.3
Cipher:         TLS_AES_256_GCM_SHA384
Key usage:      digital_signature
Ext. key usage: serverAuth
Hostname match: True

SAN:
  - example.com
  - *.example.com
```

Passing several hosts prints one `=== host ===` block per target (batch mode).

### `--file PATH` — inspect a local certificate

No live handshake, so there is no `=== host ===` header, no TLS version/cipher
and no hostname match.

```console
$ certinspect --file ./fetched.pem
Subject:        CN=example.com
Status:         VALID

Issuer:         CN=Cloudflare TLS Issuing ECC CA 3,O=SSL Corporation,C=US
Valid from:     2026-05-31 21:39:12+00:00
Valid until:    2026-08-29 21:41:26+00:00
...
```

### `--port N` / `--timeout N` — connection tuning

The report is identical to a plain inspection; only how/where certinspect
connects changes.

```console
$ certinspect example.com --port 443 --timeout 10
=== example.com ===
Subject:        CN=example.com
Status:         VALID
...
```

### `--json`

```console
$ certinspect example.com --json
[
  {
    "subject": "CN=example.com",
    "issuer": "CN=Cloudflare TLS Issuing ECC CA 3,O=SSL Corporation,C=US",
    "not_valid_before": "2026-05-31 21:39:12+00:00",
    "not_valid_after": "2026-08-29 21:41:26+00:00",
    "serial_number": 35428337808578903465180920265426569102,
    "signature_algorithm": "ecdsa-with-SHA256",
    "days_to_expire": 64,
    "validity_days": 90,
    "key_size": 256,
    "san": ["example.com", "*.example.com"],
    "fingerprint_sha256": "BE:AB:14:CF:39:67:8F:DA:...",
    "is_ca": false,
    "self_signed": false,
    "key_usage": ["digital_signature"],
    "extended_key_usage": ["serverAuth"],
    "weak": [],
    "tls_version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "hostname_match": true
  }
]
```

### `--csv` / `--csv-delimiter SEP`

```console
$ certinspect example.com github.com --csv
target,common_name,status,days_to_expire,valid_from,valid_until,issuer,hostname_match
example.com,example.com,VALID,64,2026-05-31 21:39:12+00:00,2026-08-29 21:41:26+00:00,Cloudflare TLS Issuing ECC CA 3,True
github.com,github.com,VALID,37,2026-05-05 00:00:00+00:00,2026-08-02 23:59:59+00:00,Sectigo Public Server Authentication CA DV E36,True

$ certinspect example.com --csv --csv-delimiter ';'
target;common_name;status;days_to_expire;valid_from;valid_until;issuer;hostname_match
example.com;example.com;VALID;64;2026-05-31 21:39:12+00:00;2026-08-29 21:41:26+00:00;Cloudflare TLS Issuing ECC CA 3;True
```

### `--quiet`

Healthy certificates produce no output; only problem targets (and fetch
errors) are printed.

```console
$ certinspect example.com github.com --quiet
$ echo $?
0
```

### `--verify` (+ `--cafile PATH` / `--capath DIR`)

Adds `Chain trusted` and `Revocation` to the report.

```console
$ certinspect example.com --verify
...
Hostname match: True
Chain trusted:  True
Revocation:     GOOD

SAN:
  - example.com
  - *.example.com
```

Verify against a specific CA bundle instead of the system trust store (useful
behind an internal/private PKI):

```console
$ certinspect example.com --verify --cafile /path/to/ca-bundle.pem
...
Chain trusted:  True
Revocation:     GOOD
```

### `--chain`

```console
$ certinspect example.com --chain
...
Certificate chain:
  [0] CN=example.com
      issuer:  CN=Cloudflare TLS Issuing ECC CA 3,O=SSL Corporation,C=US
      expires: 2026-08-29 21:41:26+00:00
      CA:      False
  [1] CN=Cloudflare TLS Issuing ECC CA 3,O=SSL Corporation,C=US
      issuer:  CN=SSL.com TLS Transit ECC CA R2,O=SSL Corporation,C=US
      expires: 2035-05-27 19:49:44+00:00
      CA:      True
  [2] CN=SSL.com TLS Transit ECC CA R2,O=SSL Corporation,C=US
      issuer:  CN=SSL.com TLS ECC Root CA 2022,O=SSL Corporation,C=US
      expires: 2037-10-17 17:02:22+00:00
      CA:      True
```

### `--pin SHA256`

```console
$ certinspect example.com --pin BE:AB:14:CF:39:67:8F:DA:...
...
Pin match:      True

$ certinspect example.com --pin AA:BB:CC
...
Pin match:      False
WARNING: fingerprint does not match the expected pin
$ echo $?
7
```

### `--servername NAME`

Reach a specific server by IP (or an internal DNS name) while presenting the
virtual host a load balancer routes on. The SNI hostname sent in the handshake
becomes `NAME`, and the hostname match is checked against it instead of the
connection target — handy for testing one node behind a round-robin DNS or an
ingress before it is publicly resolvable.

```console
$ certinspect 10.0.0.5 --servername api.example.com
=== 10.0.0.5 ===
Subject:        CN=api.example.com
Status:         VALID
...
Hostname match: True

SAN:
  - api.example.com
```

### `--expect-san NAME`

Assert that the certificate's SAN covers one or more names, independently of
the host you connected to. A missing name adds a warning and yields exit code 8. The flag is repeatable and honors wildcards (`*.example.com` covers
`api.example.com`). It also works with `--file`, so you can gate a certificate
before deploying it.

```console
$ certinspect example.com --expect-san www.example.com
...
Hostname match: True
Expected SAN:   ok

$ certinspect example.com --expect-san api.example.com
...
Expected SAN:   MISSING
WARNING: SAN does not cover 'api.example.com'
$ echo $?
8
```

### `--input PATH`

Read targets from a file (`#` comments allowed, `-` for stdin).

```console
$ cat hosts.txt
example.com
# a comment
github.com
$ certinspect --input hosts.txt --csv
target,common_name,status,days_to_expire,valid_from,valid_until,issuer,hostname_match
example.com,example.com,VALID,64,2026-05-31 21:39:12+00:00,2026-08-29 21:41:26+00:00,Cloudflare TLS Issuing ECC CA 3,True
github.com,github.com,VALID,37,2026-05-05 00:00:00+00:00,2026-08-02 23:59:59+00:00,Sectigo Public Server Authentication CA DV E36,True
```

### `--days N`

Tighten or relax the expiry warning window (`EXPIRING`, exit 3).

```console
$ certinspect example.com --days 90
...
Status:         EXPIRING
...
WARNING: certificate expires in 64 days
$ echo $?
3
```

### `--critical-days N`

Two-tier threshold; near-expiry escalates to `CRITICAL` (exit 4).

```console
$ certinspect example.com --days 90 --critical-days 70
...
Status:         CRITICAL
...
CRITICAL: certificate expires in 64 days
$ echo $?
4
```

### `--max-days N`

Show only certificates expiring within N days (display filter; the exit code
still reflects every target).

```console
$ certinspect example.com github.com --max-days 50 --csv
target,common_name,status,days_to_expire,valid_from,valid_until,issuer,hostname_match
github.com,github.com,VALID,37,2026-05-05 00:00:00+00:00,2026-08-02 23:59:59+00:00,Sectigo Public Server Authentication CA DV E36,True
```

### `--sort host|expiry`

Reorder the output (soonest expiry first shown here).

```console
$ certinspect example.com github.com --sort expiry --csv
target,common_name,status,days_to_expire,valid_from,valid_until,issuer,hostname_match
github.com,github.com,VALID,37,2026-05-05 00:00:00+00:00,2026-08-02 23:59:59+00:00,Sectigo Public Server Authentication CA DV E36,True
example.com,example.com,VALID,64,2026-05-31 21:39:12+00:00,2026-08-29 21:41:26+00:00,Cloudflare TLS Issuing ECC CA 3,True
```

### `--summary`

One-line tally on stderr, counting every target before filtering.

```console
$ certinspect example.com doesnotexist.invalid --summary --csv
error: doesnotexist.invalid: [Errno 8] nodename nor servname provided, or not known
target,common_name,status,days_to_expire,valid_from,valid_until,issuer,hostname_match
example.com,example.com,VALID,64,2026-05-31 21:39:12+00:00,2026-08-29 21:41:26+00:00,Cloudflare TLS Issuing ECC CA 3,True
summary: 1 valid · 0 expiring · 0 expired · 1 error (2 targets)
```

### `--export PATH`

Save the fetched certificate as PEM and still print the report.

```console
$ certinspect example.com --export ./fetched.pem
=== example.com ===
Subject:        CN=example.com
Status:         VALID
...
$ head -1 ./fetched.pem
-----BEGIN CERTIFICATE-----
```

### `--starttls {smtp,imap,pop3,ftp}`

Upgrade a plaintext protocol to TLS before inspecting (the protocol's standard
port is used unless `--port` is given).

```console
$ certinspect smtp.gmail.com --starttls smtp
=== smtp.gmail.com ===
Subject:        CN=smtp.gmail.com
Status:         VALID

Issuer:         CN=WE2,O=Google Trust Services,C=US
Valid from:     2026-06-08 08:38:06+00:00
Valid until:    2026-08-31 08:38:05+00:00
Days to expiry: 65
...
```

### `--concurrency N`

Inspect hosts in parallel in batch mode; the output is identical to the
sequential run (order is preserved), only faster. The speedup grows with the
number of hosts and their latency. Measured here on a 20-host list (the normal
per-host report is sent to `/dev/null` to focus on wall-clock time):

```console
$ cat hosts.txt
example.com
github.com
pypi.org
wikipedia.org
cloudflare.com
mozilla.org
python.org
djangoproject.com
debian.org
archlinux.org
rust-lang.org
nodejs.org
gitlab.com
stackoverflow.com
reddit.com
apache.org
postgresql.org
docker.com
kubernetes.io
php.net

$ time certinspect --input hosts.txt >/dev/null            # sequential (default)
real 1.35

$ time certinspect --input hosts.txt --concurrency 20 >/dev/null
real 0.32
```

Same 20 certificates, ~4× faster. Without the redirect you still get the usual
`=== host ===` report for every target, in the original input order.

### `--exporter {nagios,prometheus}`

Machine-readable monitoring output (full examples in
[Monitoring](#monitoring)).

```console
$ certinspect example.com --exporter nagios
OK: example.com certificate VALID (64 days to expiry) | days=64;30;0
```

### `--version`

```console
$ certinspect --version
certinspect 1.0.1
```

### Fetch error (`exit 1`)

An unreachable target prints an `error:` line to stderr and yields exit code 1;
in batch mode the other targets are still inspected.

```console
$ certinspect doesnotexist.invalid
error: doesnotexist.invalid: [Errno 8] nodename nor servname provided, or not known
$ echo $?
1
```

## Monitoring

Use `--exporter` to plug `certinspect` straight into a monitoring stack. Both
formats report every target, including hosts that could not be reached.

`nagios` emits one Nagios/Icinga plugin line per target with perfdata and exits
with the plugin convention (`0` OK, `1` WARNING, `2` CRITICAL); an unreachable
host is CRITICAL:

```console
$ certinspect example.com expired.example.com --exporter nagios
OK: example.com certificate VALID (217 days to expiry) | days=217;30;0
CRITICAL: expired.example.com certificate EXPIRED (-3 days to expiry) | days=-3;30;0
```

`prometheus` emits textfile-collector metrics (`certinspect_up`,
`certinspect_cert_expiry_days`, `certinspect_cert_valid`), keeping the normal
worst-status exit code:

```console
$ certinspect example.com --exporter prometheus
# HELP certinspect_up Whether the target could be inspected (1) or not (0).
# TYPE certinspect_up gauge
certinspect_up{target="example.com"} 1
# HELP certinspect_cert_expiry_days Days until the certificate expires.
# TYPE certinspect_cert_expiry_days gauge
certinspect_cert_expiry_days{target="example.com"} 217
# HELP certinspect_cert_valid Whether the certificate is within its validity window (1) or not (0).
# TYPE certinspect_cert_valid gauge
certinspect_cert_valid{target="example.com"} 1
```

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
| 8    | Expected SAN missing (`--expect-san`)     |

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

## Recipes

A few one-liners for the terminally curious.

```bash
# Sort a whole fleet by soonest expiry, JSON straight into jq
certinspect --input fleet.txt --concurrency 20 --json \
  | jq -r 'sort_by(.days_to_expire)[] | "\(.days_to_expire)d  \(.subject)"'

# Fail a CI job if anything expires within 14 days (exit 3) or worse
certinspect --input fleet.txt --days 14 --quiet || exit 1

# Gate a deploy: fail (exit 8) unless the new cert covers every required name
certinspect --file ./new-cert.pem \
  --expect-san example.com --expect-san www.example.com --expect-san api.example.com

# Check a single node behind a load balancer by IP, validating the vhost
certinspect 10.0.0.5 --servername api.example.com --verify

# Grab just the SHA-256 fingerprint to pin it later
certinspect example.com --json | jq -r '.[0].fingerprint_sha256'

# Daily cron: refresh Prometheus textfile metrics for node_exporter
certinspect --input fleet.txt --concurrency 20 --exporter prometheus \
  > /var/lib/node_exporter/textfile/certinspect.prom

# Nightly email digest of everything expiring within 30 days
certinspect --input fleet.txt --max-days 30 --sort expiry --summary \
  | mail -s "Certs expiring soon" ops@example.com
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the release history.

## Development

```bash
# Tests
pytest

# Lint and formatting (Ruff)
ruff check src tests
ruff format src tests
```

## Support

If certinspect is useful to you, the best ways to support it are:

- Star the repo to help others discover it
- [Open an issue](https://github.com/mangrisano/certinspect/issues) for bugs or ideas
- Send a pull request
- Share it with others who manage TLS certificates

## License

MIT — see [LICENSE](LICENSE).
