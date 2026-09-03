<div align="center">

<img src="https://raw.githubusercontent.com/mangrisano/certinspect/main/docs/logo.svg" alt="certinspect" width="440">

[![CI](https://github.com/mangrisano/certinspect/actions/workflows/ci.yml/badge.svg)](https://github.com/mangrisano/certinspect/actions/workflows/ci.yml)
[![Performance](https://github.com/mangrisano/certinspect/actions/workflows/performance.yml/badge.svg)](https://github.com/mangrisano/certinspect/actions/workflows/performance.yml)
[![PyPI](https://img.shields.io/pypi/v/certinspect.svg?cacheSeconds=3600)](https://pypi.org/project/certinspect/)
[![Python](https://img.shields.io/pypi/pyversions/certinspect.svg?cacheSeconds=3600)](https://pypi.org/project/certinspect/)
[![Downloads](https://static.pepy.tech/badge/certinspect)](https://pepy.tech/project/certinspect)
[![License: MIT](https://img.shields.io/pypi/l/certinspect.svg)](LICENSE)

**TLS inspection · Expiry alerts · OCSP/CRL revocation · Chain of trust · Batch & concurrency · STARTTLS · CI-friendly exit codes**

[PyPI](https://pypi.org/project/certinspect/) · [Usage](#usage) · [Use cases](#use-cases) · [Options](#options) · [Recipes](#recipes) · [Exit codes](#exit-codes) · [Changelog](#changelog) · [Issues](https://github.com/mangrisano/certinspect/issues)

<img src="https://raw.githubusercontent.com/mangrisano/certinspect/main/docs/demo.gif" alt="certinspect demo" width="760">

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

## Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Example](#example)
- [Use cases](#use-cases)
  - [Keep a whole fleet from expiring](#keep-a-whole-fleet-from-expiring)
  - [Fail a CI build before a cert bites you](#fail-a-ci-build-before-a-cert-bites-you)
  - [Validate a freshly issued cert before deploying it](#validate-a-freshly-issued-cert-before-deploying-it)
  - [Check one node behind a load balancer / anycast IP](#check-one-node-behind-a-load-balancer--anycast-ip)
  - [Inspect services behind an internal / private PKI](#inspect-services-behind-an-internal--private-pki)
  - [Catch a revoked certificate](#catch-a-revoked-certificate)
  - [Spot an expired intermediate before it breaks the chain](#spot-an-expired-intermediate-before-it-breaks-the-chain)
  - [Inspect mail / FTP servers (STARTTLS)](#inspect-mail--ftp-servers-starttls)
  - [Pin a certificate and alert on unexpected changes](#pin-a-certificate-and-alert-on-unexpected-changes)
  - [Feed a monitoring stack](#feed-a-monitoring-stack)
  - [Audit a fleet into a spreadsheet](#audit-a-fleet-into-a-spreadsheet)
  - [Separate a warning window from a critical one](#separate-a-warning-window-from-a-critical-one)
  - [Send a nightly expiry digest](#send-a-nightly-expiry-digest)
  - [Pipe results into other tooling](#pipe-results-into-other-tooling)
  - [Inspect a service on a non-standard TLS port](#inspect-a-service-on-a-non-standard-tls-port)
  - [Probe slow or high-latency endpoints](#probe-slow-or-high-latency-endpoints)
  - [Debug the exact chain a server presents](#debug-the-exact-chain-a-server-presents)
  - [Archive the served certificate](#archive-the-served-certificate)
- [Options](#options)
- [Options in action](#options-in-action)
  - [`target`](#target--inspect-a-host)
  - [`--file`](#--file-path--inspect-a-local-certificate)
  - [`--port` / `--timeout`](#--port-n----timeout-n--connection-tuning)
  - [`--json`](#--json)
  - [`--csv` / `--csv-delimiter`](#--csv----csv-delimiter-sep)
  - [`--quiet`](#--quiet)
  - [`--verify`](#--verify----cafile-path----capath-dir)
  - [`--chain`](#--chain)
  - [`--pin`](#--pin-sha256)
  - [`--servername`](#--servername-name)
  - [`--client-cert` / `--client-key`](#--client-cert-path----client-key-path)
  - [`--proxy` / `--no-proxy`](#--proxy-url----no-proxy)
  - [`--expect-san`](#--expect-san-name)
  - [`--not-after-max`](#--not-after-max-n)
  - [`--cab-forum`](#--cab-forum)
  - [`--min-key-size`](#--min-key-size-n)
  - [`--fail-weak`](#--fail-weak)
  - [`--require-sct`](#--require-sct)
  - [`--require-must-staple`](#--require-must-staple)
  - [`--require-revocation-check`](#--require-revocation-check)
  - [`--min-tls-version`](#--min-tls-version-ver)
  - [`--profile`](#--profile-lenientstandardstrict)
  - [`--input`](#--input-path)
  - [`--days`](#--days-n)
  - [`--critical-days`](#--critical-days-n)
  - [`--max-days`](#--max-days-n)
  - [`--sort`](#--sort-hostexpiry)
  - [`--summary`](#--summary)
  - [`--field`](#--field-name)
  - [`--exit-zero`](#--exit-zero)
  - [`--export`](#--export-path)
  - [`--starttls`](#--starttls-smtpimappop3ftp)
  - [`--concurrency`](#--concurrency-n)
  - [`--exporter`](#--exporter-nagiosprometheus)
  - [`--version`](#--version)
- [Monitoring](#monitoring)
- [Exit codes](#exit-codes)
- [Recipes](#recipes)
- [Changelog](#changelog)
- [Development](#development)
- [Support](#support)
- [License](#license)

## Features

| Area               | What you get                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Certificate facts  | Validity & days to expiry, total validity period, subject & issuer, SAN (DNS and IP), SHA-256 fingerprint, CA / self-signed flags, key usage & extended key usage, embedded Certificate Transparency SCT count, OCSP Must-Staple flag                                                                                                                                                                                                                                                                                     |
| Crypto health      | Signature algorithm & key size, weak-crypto warnings, negotiated TLS version & cipher                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Trust & revocation | Chain verification + OCSP/CRL revocation against the system trust store (on by default; `--no-verify` to skip), or a private/internal CA bundle (`--cafile`/`--capath`); offline chain validation of a local bundle with `--file`; show the chain (`--chain`)                                                                                                                                                                                                                                                             |
| Chain hygiene      | Warn about expired or soon-to-expire intermediate/root CA certificates in the chain; diagnose _why_ an untrusted chain failed (incomplete / mismatched / untrusted-root / expired) with a fix suggestion                                                                                                                                                                                                                                                                                                                  |
| Identity checks    | Hostname match against the certificate, SHA-256 fingerprint pinning (`--pin`), SAN coverage assertions (`--expect-san`), SNI override for backends behind a load balancer (`--servername`)                                                                                                                                                                                                                                                                                                                                |
| Policy enforcement | Opt-in checks that fail (exit code 9): maximum total validity (`--not-after-max`, or `--cab-forum` for the date-aware CA/Browser Forum cap), minimum key size (`--min-key-size`), promote weak-crypto warnings to failures (`--fail-weak`), require embedded Certificate Transparency SCTs (`--require-sct`), require the OCSP Must-Staple extension (`--require-must-staple`), require a definitive revocation verdict (`--require-revocation-check`), or enforce a minimum negotiated TLS version (`--min-tls-version`) |
| Policy profiles    | Turn on a whole hardening level with one flag (`--profile lenient`/`standard`/`strict`); a plain intensity ladder, not a compliance attestation, and explicit policy flags still override the profile                                                                                                                                                                                                                                                                                                                     |
| Batch & speed      | Inspect many hosts at once, in parallel (`--concurrency`), from args or a file (`--input`)                                                                                                                                                                                                                                                                                                                                                                                                                                |
| Discovery          | Enumerate a domain's certificates from Certificate Transparency logs (crt.sh) and inspect each host, or list the CT inventory without connecting (`--discover`, `--discover-only`), surfacing forgotten or shadow certificates and unexpected issuers                                                                                                                                                                                                                                                                     |
| Output formats     | Plain text, JSON (`--json`), CSV (`--csv`), single-field lines for scripting (`--field`), Nagios/Icinga & Prometheus (`--exporter`)                                                                                                                                                                                                                                                                                                                                                                                       |
| Triage helpers     | Only certs expiring within N days (`--max-days`), sort by host or soonest expiry (`--sort`), one-line tally (`--summary`), tighter CRITICAL threshold (`--critical-days`)                                                                                                                                                                                                                                                                                                                                                 |
| Protocols          | Direct TLS plus STARTTLS — SMTP, IMAP, POP3, FTP (`--starttls`)                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Connectivity       | Mutual-TLS client certificates (`--client-cert`/`--client-key`) and HTTP CONNECT proxy tunnelling — explicit (`--proxy`) or from the environment (`HTTPS_PROXY`/`NO_PROXY`, like curl; `--no-proxy` to opt out) — for hosts behind a corporate/cloud egress proxy                                                                                                                                                                                                                                                         |
| Automation         | Meaningful exit codes for cron/CI (or force success with `--exit-zero`), no telemetry, single runtime dependency                                                                                                                                                                                                                                                                                                                                                                                                          |

## Requirements

- Python >= 3.12

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

# JSON output (schema-2 envelope; per-target objects under .results)
certinspect example.com --json

# CSV output (one row per target, with a header) for spreadsheets
certinspect example.com github.com --csv

# CSV with a ';' separator (Numbers/Excel in some locales, e.g. Italian)
certinspect example.com github.com --csv --csv-delimiter ';'

# Inspect a local certificate
certinspect --file ./certificate.pem

# Or pipe a certificate in from stdin
openssl s_client -connect example.com:443 </dev/null 2>/dev/null | certinspect --file -

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

# Enforce a whole hardening level with a single flag (fails with exit 9)
certinspect example.com --profile standard

# A profile just presets the opt-in policy flags; any explicit flag wins
certinspect example.com --profile strict --min-key-size 3072

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

By default certinspect opens a fully verified TLS handshake (chain +
hostname against the Python/OpenSSL trust store) and, when the certificate
advertises an OCSP responder, queries it for the revocation status. If OCSP is
unavailable, certinspect falls back to the certificate's CRL distribution
points (downloaded over HTTP and verified against the issuer). Both checks are
soft-fail: when neither OCSP nor the CRL gives an answer the status is
`UNAVAILABLE` and the exit code is unchanged, while a `REVOKED` status fails
with exit code 6. A stale OCSP response (its `nextUpdate` already in the past)
is treated as `UNAVAILABLE` too, so a replayed answer cannot mask a later
revocation. The OCSP/CRL/CA-Issuer URLs come from the certificate, so
certinspect refuses to follow one that resolves to a loopback, link-local
(cloud metadata) or otherwise non-routable address, and caps the download
size — private/internal PKI addresses stay reachable.

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

When a chain fails to verify, certinspect classifies _why_ into a
`chain_diagnosis` with a machine-readable `code` and a human `detail`, turning a
raw OpenSSL error into an actionable root cause:

| Code               | Meaning                                             | Remedy                                                        |
| ------------------ | --------------------------------------------------- | ------------------------------------------------------------- |
| `INCOMPLETE_CHAIN` | only the leaf was sent; its intermediate is missing | make the server send its intermediate (the AIA URL is shown)  |
| `CHAIN_MISMATCH`   | the sent intermediates do not sign the leaf         | install the correct intermediate for the leaf's issuer        |
| `UNTRUSTED_ROOT`   | the chain is complete but its root is not trusted   | pass `--cafile` for an internal CA, or update the trust store |
| `EXPIRED_IN_CHAIN` | a certificate in the chain has expired              | renew/replace the expired certificate                         |

```console
$ certinspect broken.example.com --verify
=== broken.example.com ===
Subject:        CN=*.example.com
...
Chain trusted:  False
WARNING: chain not trusted (unable to get local issuer certificate)
Chain diagnosis: CHAIN_MISMATCH
  -> the server sent intermediate(s) 'Other CA G3' that do not sign the leaf; its real issuer 'Real Issuing CA' is absent from the chain
```

(The presented chain is exposed by Python 3.13+, so the diagnosis is available
there; on older interpreters only `chain_trusted`/`chain_error` are reported.)

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

When the file is a full bundle (leaf + intermediates + root, e.g. exported from
a PKCS#12), add `--verify` to validate the whole chain **offline** — the same
check `openssl verify` performs, without a live handshake:

```console
$ certinspect --file ./bundle.pem --verify
Subject:        CN=example.com
Status:         VALID
...
Chain trusted:  True
```

A bundle missing its intermediate fails with exit `6` and an actionable
diagnosis instead of a cryptic error:

```console
$ certinspect --file ./leaf-only.pem --verify
...
Chain trusted:  False
WARNING: chain not trusted (validation failed: candidates exhausted: ...)
Chain diagnosis:INCOMPLETE_CHAIN
  -> the server sent only the leaf; the intermediate 'GeoTrust TLS RSA CA G1'
     is missing and is published at http://cacerts.geotrust.com/...crt
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
certinspect revoked.example.com --verify
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

The JSON is a versioned envelope; the per-target objects live under `.results`
— feed it to [`jpick`](https://github.com/mangrisano/jpick) (a jq-like JSON
tool), a dashboard or a script:

```bash
# Every host, soonest expiry first (certinspect sorts, jpick formats)
certinspect --input fleet.txt --concurrency 20 --sort expiry --json \
  | jpick -r '.results[] | "\(.validity.days_to_expiry)d  \(.subject)"'

# Grab just the SHA-256 fingerprint (e.g. to pin it later)
certinspect example.com --json | jpick -r '.results[0].fingerprint_sha256'
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
certinspect broken.example.com --chain
```

### Archive the served certificate

Save the fetched leaf as PEM for auditing, diffing or extracting a pin:

```bash
certinspect example.com --export ./example.com.pem
```

## Options

| Option                                | Description                                                                                                                                                                                                                                                       |
| ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `target...`                           | One or more domains, URLs or `host:port` to inspect. Omit when using `--file`.                                                                                                                                                                                    |
| `--file PATH`                         | Inspect a local certificate (PEM or DER) instead of a host. Use `-` to read the certificate from standard input.                                                                                                                                                  |
| `--port N`                            | TCP port to connect to (default: 443).                                                                                                                                                                                                                            |
| `--timeout N`                         | Connection timeout in seconds (default: 5). Used for both connect and read unless the two below are set.                                                                                                                                                          |
| `--connect-timeout N`                 | TCP connect timeout in seconds (default: `--timeout`).                                                                                                                                                                                                            |
| `--read-timeout N`                    | Handshake/read timeout in seconds (default: `--timeout`).                                                                                                                                                                                                         |
| `--retries N`                         | Retry transient connection failures (timeouts, refused/reset, DNS) this many times (default: 0).                                                                                                                                                                  |
| `--json`                              | Print the result as JSON instead of human-readable text.                                                                                                                                                                                                          |
| `--csv`                               | Print the results as CSV (one row per target, with a header).                                                                                                                                                                                                     |
| `--csv-delimiter SEP`                 | Field separator for `--csv` (default `,`). Use `;` for Numbers/Excel in locales that expect it.                                                                                                                                                                   |
| `--quiet`                             | Only print certificates that have a problem.                                                                                                                                                                                                                      |
| `--schema {1,2}`                      | JSON schema version for `--json` (default `2`, the nested/versioned document). `--schema 1` is the legacy flat array.                                                                                                                                             |
| `--verify`                            | Force chain verification (already the default). A verified handshake plus OCSP/CRL revocation for a host, or the bundle validated offline for `--file`.                                                                                                           |
| `--no-verify`                         | Skip chain verification (and revocation for hosts); only inspect the certificate itself.                                                                                                                                                                          |
| `--cafile PATH`                       | Verify the chain against this CA bundle (PEM) instead of the system trust store; for internal/private PKI. Incompatible with `--no-verify`.                                                                                                                       |
| `--capath DIR`                        | Verify the chain against the hashed CA certificates in this directory (OpenSSL `c_rehash` layout). Incompatible with `--no-verify`; may be combined with `--cafile`.                                                                                              |
| `--chain`                             | Show the certificate chain: presented by the server for a host, or every certificate in the bundle for `--file`.                                                                                                                                                  |
| `--client-cert PATH`                  | Present a client certificate (PEM) for mutual-TLS endpoints (host targets only). Use `--client-key` when the key is stored separately.                                                                                                                            |
| `--client-key PATH`                   | Private key (PEM) for `--client-cert` when stored separately from the certificate.                                                                                                                                                                                |
| `--proxy URL`                         | Tunnel the connection through an HTTP CONNECT proxy, e.g. `http://proxy:8080` or `http://user:pass@proxy:8080` (host targets only). Without it, the environment proxy (`HTTPS_PROXY`, honouring `NO_PROXY`) is used, like curl.                                   |
| `--no-proxy`                          | Force a direct connection, ignoring any proxy set in the environment. Mutually exclusive with `--proxy`.                                                                                                                                                          |
| `--pin SHA256`                        | Fail (exit 7) unless the SHA-256 fingerprint matches (colons/case ignored).                                                                                                                                                                                       |
| `--servername NAME`                   | Override the SNI hostname sent in the handshake (hosts only); the hostname match is checked against `NAME`. For reaching a backend by IP behind a load balancer.                                                                                                  |
| `--expect-san NAME`                   | Assert the certificate's SAN covers `NAME` (wildcards honored); exit 8 if missing. Repeatable; works for host and `--file` targets.                                                                                                                               |
| `--not-after-max N`                   | Fail (exit 9) when the total validity exceeds N days (use 398 for the CA/Browser Forum maximum). Opt-in; works for host and `--file` targets.                                                                                                                     |
| `--cab-forum`                         | Fail (exit 9) when the total validity exceeds the CA/Browser Forum maximum in effect today (398 days now, then 200, 100 and 47 on 2026/2027/2029-03-15). Date-aware shorthand for `--not-after-max`; mutually exclusive with it.                                  |
| `--min-key-size N`                    | Fail (exit 9) when the public key is smaller than N bits (e.g. 2048 for RSA). Opt-in.                                                                                                                                                                             |
| `--fail-weak`                         | Turn the weak-crypto warnings (small key, SHA-1/MD5 signature) into a hard failure (exit 9) instead of a mere warning.                                                                                                                                            |
| `--require-sct`                       | Fail (exit 9) when the certificate embeds no Signed Certificate Timestamps (Certificate Transparency). Checks embedded SCTs only, not those from the TLS handshake or OCSP. Opt-in.                                                                               |
| `--require-must-staple`               | Fail (exit 9) when the certificate lacks the OCSP Must-Staple extension (RFC 7633 TLS Feature `status_request`). Opt-in.                                                                                                                                          |
| `--require-revocation-check`          | Fail (exit 9) unless OCSP or CRL returns a definitive `GOOD` revocation verdict. Host targets only; incompatible with `--no-verify`. Opt-in.                                                                                                                      |
| `--min-tls-version VER`               | Fail (exit 9) when the connection negotiates a TLS version older than `VER` (`TLSv1`, `TLSv1.1`, `TLSv1.2`, `TLSv1.3`). Host targets only; opt-in.                                                                                                                |
| `--profile {lenient,standard,strict}` | Apply a named bundle of the opt-in policy checks in one go (exit 9 on violation). Intensity ladder, not an official standard; explicit flags override it. See [Policy profiles](#policy-profiles).                                                                |
| `--input PATH`                        | Read extra targets from a file, one per line ('-' for stdin).                                                                                                                                                                                                     |
| `--discover DOMAIN`                   | Discover hostnames from Certificate Transparency logs (crt.sh) for DOMAIN and inspect each one, surfacing forgotten or shadow certificates. Repeatable; host targets only.                                                                                        |
| `--discover-only`                     | With `--discover`, list the CT inventory (expiry, issuer, hostnames, soonest expiry first, wildcards included) for the domain(s) without connecting, then exit. Good for a fast audit or spotting a certificate from an unexpected CA. Supports `--json`/`--csv`. |
| `--expect-issuer SUBSTRING`           | With `--discover-only`, flag any certificate whose issuer matches none of these substrings (case-insensitive) and exit 9 — a Certificate Transparency mis-issuance check. Repeatable.                                                                             |
| `--discover-timeout N`                | Timeout in seconds for the `--discover` crt.sh query (default: 30), separate from `--timeout` since a log search can be slower than a handshake.                                                                                                                  |
| `--days N`                            | Warn if the certificate expires within N days (default: 30).                                                                                                                                                                                                      |
| `--critical-days N`                   | Escalate to CRITICAL (exit code 4) when the certificate expires within N days. Must be `<= --days`; feeds Nagios CRITICAL and the `--summary` `critical` count.                                                                                                   |
| `--max-days N`                        | Only show certificates expiring within N days (expired ones always shown; filters display only).                                                                                                                                                                  |
| `--sort host\|expiry`                 | Sort the output by host (alphabetical) or by soonest expiry (display only; does not affect exit code).                                                                                                                                                            |
| `--summary`                           | Print a one-line tally (valid/expiring/expired/errors) to stderr; counts every target before filtering.                                                                                                                                                           |
| `--field NAME`                        | Print only the given field(s), one tab-separated line per target (repeatable; `target` for the host). For scripting without a JSON tool.                                                                                                                          |
| `--exit-zero`                         | Always exit 0, even on problems or fetch errors. Report-only mode for dashboards/CI that read the output, not the exit code.                                                                                                                                      |
| `--export PATH`                       | Save the inspected certificate as a PEM file at PATH.                                                                                                                                                                                                             |
| `--starttls {smtp,imap,pop3,ftp}`     | Upgrade a plaintext connection to TLS before inspecting (standard port unless `--port` is given).                                                                                                                                                                 |
| `--exporter {nagios,prometheus}`      | Emit machine-readable monitoring output (ignores `--quiet`).                                                                                                                                                                                                      |
| `--concurrency N`                     | Inspect up to N hosts in parallel in batch mode (default: 1; order is preserved).                                                                                                                                                                                 |
| `--version`                           | Print the version and exit.                                                                                                                                                                                                                                       |

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
Chain trusted:  True
Revocation:     GOOD

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

When the file is a bundle carrying the whole chain (leaf, intermediates and
root — for example a PEM exported from a PKCS#12), `--verify` validates that
chain **offline** and `--chain` lists every certificate in it (see
[`--verify`](#--verify----cafile-path----capath-dir) and [`--chain`](#--chain)).

### `--port N` / `--timeout N` — connection tuning

The report is identical to a plain inspection; only how/where certinspect
connects changes. Split the single `--timeout` into `--connect-timeout` and
`--read-timeout` to fail fast on dead hosts while still allowing a slow
handshake (requests-style), and add `--retries` to ride out transient network
blips instead of reporting a false failure.

```console
$ certinspect example.com --connect-timeout 3 --read-timeout 10 --retries 2
=== example.com ===
Subject:        CN=example.com
Status:         VALID
...
```

### `--json`

The JSON output is a versioned document: an envelope with `schema_version`,
the producing `certinspect_version`, and a `results` array (one object per
target). Fields are grouped by domain, dates are ISO 8601 and the serial
number is a string to avoid precision loss. Since verification is on by
default, `chain` and `revocation` appear unless you pass `--no-verify`.

```console
$ certinspect example.com --json
{
  "schema_version": 2,
  "certinspect_version": "2.0.0",
  "results": [
    {
      "target": "example.com",
      "status": "VALID",
      "subject": "CN=example.com",
      "issuer": "CN=Cloudflare TLS Issuing ECC CA 3,O=SSL Corporation,C=US",
      "serial_number": "35428337808578903465180920265426569102",
      "fingerprint_sha256": "BE:AB:14:CF:39:67:8F:DA:...",
      "self_signed": false,
      "is_ca": false,
      "san": ["example.com", "*.example.com"],
      "key": {
        "size": 256,
        "signature_algorithm": "ecdsa-with-SHA256",
        "usage": ["digital_signature"],
        "extended_usage": ["serverAuth"],
        "weak": []
      },
      "validity": {
        "not_before": "2026-05-31T21:39:12+00:00",
        "not_after": "2026-08-29T21:41:26+00:00",
        "days_to_expiry": 64,
        "total_days": 90
      },
      "sct_count": 2,
      "must_staple": false,
      "hostname_match": true,
      "connection": {"tls_version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384"},
      "chain": {"trusted": true, "error": null, "diagnosis": null, "warnings": []},
      "revocation": {"status": "GOOD", "detail": null}
    }
  ]
}
```

The `status` field mirrors the human report's `Status` line (`VALID`,
`EXPIRING`, `CRITICAL`, `EXPIRED`, `NOT YET VALID` or `INVALID DATES`) and
honors `--days` / `--critical-days`, so a JSON consumer gets the verdict
without re-deriving it from the dates.

Need the pre-2.0 flat array (no envelope, dates via `str()`, integer serial)?
Pass `--schema 1`:

```console
$ certinspect example.com --json --schema 1
[
  {
    "subject": "CN=example.com",
    "not_valid_before": "2026-05-31 21:39:12+00:00",
    "status": "VALID"
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

### `--verify` / `--no-verify` (+ `--cafile PATH` / `--capath DIR`)

Verification is on by default: a plain inspection already reports `Chain
trusted` and `Revocation` (see [`target`](#target--inspect-a-host) above). Pass
`--no-verify` to skip it and inspect only the certificate itself — the two rows
disappear:

```console
$ certinspect example.com --no-verify
...
Hostname match: True

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

With `--file`, `--verify` validates the chain contained in the bundle
**offline** (no network): the leaf is checked against the system trust store —
or `--cafile`/`--capath` for an internal PKI — using the bundle's own
intermediates, exactly like `openssl verify`. Revocation is not queried offline.

```console
$ certinspect --file ./bundle.pem --verify
...
Chain trusted:  True
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

### `--client-cert PATH` / `--client-key PATH`

Present a client certificate so certinspect can complete the handshake with a
mutual-TLS (mTLS) endpoint — internal service meshes, API gateways or admin
ports that require client authentication. Point `--client-cert` at a PEM file;
add `--client-key` when the private key lives in a separate file.

```console
$ certinspect gateway.internal --client-cert ./client.pem --client-key ./client.key
=== gateway.internal ===
Subject:        CN=gateway.internal
Status:         VALID
...
```

### `--proxy URL` / `--no-proxy`

Tunnel the TLS connection through an HTTP `CONNECT` proxy, so a host reachable
only through a corporate/cloud egress proxy can still be inspected. Basic proxy
auth is supported via `user:pass@`.

Like curl, certinspect also uses the environment proxy automatically when
`--proxy` is not given: it reads `HTTPS_PROXY`/`HTTP_PROXY` (and the system
proxy on macOS/Windows) and honours `NO_PROXY`. Use `--no-proxy` to force a
direct connection regardless of the environment.

```console
$ certinspect example.com --proxy http://proxy.corp:8080   # explicit
$ HTTPS_PROXY=http://proxy.corp:8080 certinspect example.com  # from the env
$ certinspect example.com --no-proxy                       # ignore the env proxy
```

### `--expect-san NAME`

Assert that the certificate's SAN covers one or more names, independently of
the host you connected to. A missing name adds a warning and yields exit code 8. The flag is repeatable and honors wildcards (`*.example.com` covers
`api.example.com`). IP-address SANs are covered too, so `--expect-san 10.0.0.5`
works for certificates issued to an IP. It also works with `--file`, so you can
gate a certificate before deploying it.

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

### `--not-after-max N`

Enforce a maximum total validity: a certificate whose lifetime exceeds N days
fails with exit code 9. Use `398` to match the current CA/Browser Forum limit
for publicly trusted certificates. Opt-in — without the flag the validity is
only reported, never enforced. Works with `--file` too, so you can gate a
certificate before deploying it.

```console
$ certinspect example.com --not-after-max 398
...
Total validity: 501 days
...
Policy:         FAIL
WARNING: policy violation (total validity 501 days exceeds the 398-day maximum)
$ echo $?
9
```

### `--cab-forum`

Same enforcement as `--not-after-max`, but the limit tracks the CA/Browser
Forum schedule automatically based on today's date, so you never have to update
the number as the cap shortens. The maximum lifetime drops on fixed dates:

| In effect from | Maximum validity |
| -------------- | ---------------- |
| today          | 398 days         |
| 2026-03-15     | 200 days         |
| 2027-03-15     | 100 days         |
| 2029-03-15     | 47 days          |

Mutually exclusive with `--not-after-max`. Works with `--file` too.

```console
$ certinspect example.com --cab-forum
...
Total validity: 501 days
...
Policy:         FAIL
WARNING: policy violation (total validity 501 days exceeds the 200-day maximum)
$ echo $?
9
```

### `--min-key-size N`

Fail (exit code 9) when the public key is smaller than N bits — e.g. reject
any RSA key below 2048 bit. Opt-in.

```console
$ certinspect example.com --min-key-size 2048
...
Key size:       1024 bit
...
Policy:         FAIL
WARNING: policy violation (key size 1024 bit is below the 2048-bit minimum)
$ echo $?
9
```

### `--fail-weak`

Promote the weak-crypto warnings certinspect already emits (small key,
SHA-1/MD5 signature) to a hard failure with exit code 9, so a pipeline stops on
weak certificates instead of merely printing a warning.

```console
$ certinspect example.com --fail-weak
...
WARNING: Weak key (1024 bit)
Policy:         FAIL
WARNING: policy violation (Weak key (1024 bit))
$ echo $?
9
```

### `--require-sct`

Fail (exit code 9) when the certificate embeds no Signed Certificate
Timestamps. Publicly-trusted certificates must be logged in Certificate
Transparency logs and carry SCTs, or browsers such as Chrome distrust them.
Only the SCTs embedded in the certificate are checked, not those a server may
deliver over the TLS handshake or OCSP. The embedded SCT count is always shown
as the `SCTs` row.

```console
$ certinspect internal.example.com --require-sct
...
SCTs:           none (no Certificate Transparency)
Policy:         FAIL
WARNING: policy violation (no embedded Signed Certificate Timestamps (Certificate Transparency))
$ echo $?
9
```

### `--require-must-staple`

Fail (exit code 9) when the certificate lacks the OCSP Must-Staple extension
(RFC 7633). A Must-Staple certificate forces clients to reject the connection
unless the server presents a stapled OCSP response, closing the OCSP soft-fail
hole. Whether the extension is present is always shown as the `Must-Staple`
row.

```console
$ certinspect example.com --require-must-staple
...
Must-Staple:    False
Policy:         FAIL
WARNING: policy violation (missing OCSP Must-Staple extension)
$ echo $?
9
```

### `--require-revocation-check`

Fail (exit code 9) unless OCSP or CRL returns a definitive `GOOD` revocation
verdict. By default certinspect keeps browser-like soft-fail behavior: if
responders are unavailable, malformed, stale or do not know the certificate,
the revocation row is reported but the exit code is not changed. This option
turns that uncertainty into a policy failure for stricter CI or audit jobs.

```console
$ certinspect example.com --require-revocation-check
...
Revocation:     UNAVAILABLE
Policy:         FAIL
WARNING: policy violation (revocation check did not return GOOD (UNAVAILABLE: OCSP request failed))
$ echo $?
9
```

### `--min-tls-version VER`

Fail (exit code 9) when the TLS handshake negotiates a version older than
`VER`, so a pipeline can reject servers still speaking legacy TLS. Host targets
only, as it needs a live handshake. The negotiated version is always shown as
the `TLS version` row.

```console
$ certinspect legacy.example.com --min-tls-version TLSv1.2
...
TLS version:    TLSv1.1
Policy:         FAIL
WARNING: policy violation (TLS version TLSv1.1 is below the required TLSv1.2)
$ echo $?
9
```

### `--profile {lenient,standard,strict}`

A profile turns on a whole bundle of the opt-in policy checks with a single
flag, so a common hardening level is one option away instead of a long list of
flags. A violation of any bundled check fails with exit code 9, exactly as if
you had passed the flags yourself.

> **These names are an intensity ladder, not an official standard.** They are
> hand-picked presets chosen by this project, and passing one is **not** a
> compliance attestation (PCI DSS, Mozilla, NIST, ...). certinspect only sees
> the certificate and the TLS handshake, so a profile can never cover the parts
> of any standard that concern server configuration or the wider environment.
> The choices are _informed_ by widely used guidance — the CA/Browser Forum
> Baseline Requirements (validity cap), Certificate Transparency (SCTs), and
> the common "no early TLS / strong crypto" baseline echoed by PCI DSS and the
> Mozilla server-side TLS guidelines — but the exact mapping below is ours.

Each stricter tier is a superset of the one below it:

| Check (flag)                                  | `lenient` | `standard` |  `strict`   |
| --------------------------------------------- | :-------: | :--------: | :---------: |
| Minimum TLS version (`--min-tls-version`)     |  TLSv1.2  |  TLSv1.2   | **TLSv1.3** |
| Fail on weak crypto (`--fail-weak`)           |    yes    |    yes     |     yes     |
| Minimum key size (`--min-key-size`)           |     —     |  2048 bit  |  2048 bit   |
| Require CT SCTs (`--require-sct`)             |     —     |     —      |     yes     |
| CA/Browser Forum validity cap (`--cab-forum`) |     —     |     —      |     yes     |

Precedence and edge cases a sysadmin should know:

- **Explicit flags always win.** A profile only fills in options you left at
  their default, so `--profile strict --min-key-size 3072` keeps your 3072-bit
  floor.
- **`--file` targets skip the TLS-version check** (there is no live handshake
  to measure); every other bundled check still applies to a local certificate.
- **`strict` implies `--cab-forum`.** If you also pass an explicit
  `--not-after-max N`, your value takes precedence and the two stay mutually
  exclusive.
- **No profile is applied by default** — without `--profile` none of these
  checks run and the exit code is unaffected.

```console
$ certinspect example.com --profile standard
...
Key size:       1024 bit
TLS version:    TLSv1.3
Policy:         FAIL
WARNING: policy violation (key size 1024 bit is below the 2048-bit minimum)
WARNING: policy violation (Weak key (1024 bit))
$ echo $?
9
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

### `--field NAME`

Print only the fields you ask for, one tab-separated line per target, so you
can pull values straight into a script without a JSON tool. Repeat `--field`
for several columns; the pseudo-field `target` is the inspected host and list
fields (like `san`) are comma-joined.

```console
$ certinspect example.com github.com --field target --field days_to_expire --field status
example.com	64	VALID
github.com	37	VALID

$ certinspect example.com --field days_to_expire
64
```

### `--exit-zero`

Run every check and print the report as usual, but always exit 0 — even for
expired certs or unreachable hosts. Useful when a dashboard or CI step reads
the output and you don't want the process to fail.

```console
$ certinspect expired.example.com --exit-zero
=== expired.example.com ===
Subject:        CN=expired.example.com
Status:         EXPIRED
...
$ echo $?
0
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

Three further gauges appear only for the targets whose check actually ran, so a
scrape never carries a misleading `0` for a check that was not requested:
`certinspect_hostname_match` (host targets), and — with `--verify` —
`certinspect_chain_trusted` and `certinspect_cert_revoked` (the latter only when
OCSP/CRL returns a definitive answer). This lets you alert directly on chain,
hostname and revocation problems without parsing text:

```console
$ certinspect example.com --verify --exporter prometheus
# ... certinspect_up / cert_expiry_days / cert_valid as above ...
# HELP certinspect_hostname_match Whether the hostname is covered by the certificate SAN (1) or not (0).
# TYPE certinspect_hostname_match gauge
certinspect_hostname_match{target="example.com"} 1
# HELP certinspect_chain_trusted Whether the certificate chain is trusted (1) or not (0).
# TYPE certinspect_chain_trusted gauge
certinspect_chain_trusted{target="example.com"} 1
# HELP certinspect_cert_revoked Whether the certificate is revoked (1) or not (0).
# TYPE certinspect_cert_revoked gauge
certinspect_cert_revoked{target="example.com"} 0
```

A `certinspect_policy_ok` gauge follows the same rule: it appears only when
policy checks are requested (`--not-after-max`/`--cab-forum`, `--min-key-size`,
`--fail-weak`, `--require-sct`, `--require-must-staple`, `--min-tls-version`),
reporting `1` when the target passed them all and `0` when it violated at least
one — so you can alert on policy breaches directly:

```console
$ certinspect example.com --min-key-size 4096 --exporter prometheus
# ... certinspect_up / cert_expiry_days / cert_valid as above ...
# HELP certinspect_policy_ok Whether the certificate passed the requested policy checks (1) or not (0).
# TYPE certinspect_policy_ok gauge
certinspect_policy_ok{target="example.com"} 0
```

## Exit codes

Designed for automation (cron, CI, monitoring scripts). In batch mode the
worst code across all targets is returned.

| Code | Meaning                                                                                                                                            |
| ---- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0    | Valid certificate                                                                                                                                  |
| 1    | Runtime error (network, file, parse)                                                                                                               |
| 2    | Command-line usage error                                                                                                                           |
| 3    | Expiring within the `--days` threshold                                                                                                             |
| 4    | Expired, not yet valid, or with invalid dates                                                                                                      |
| 5    | Hostname does not match the certificate                                                                                                            |
| 6    | Chain not trusted or revoked (`--verify`)                                                                                                          |
| 7    | Fingerprint does not match `--pin`                                                                                                                 |
| 8    | Expected SAN missing (`--expect-san`)                                                                                                              |
| 9    | Policy violation (`--not-after-max`/`--cab-forum`, `--min-key-size`, `--fail-weak`, `--require-sct`, `--require-must-staple`, `--min-tls-version`) |

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
# Sort a whole fleet by soonest expiry, JSON straight into jpick
certinspect --input fleet.txt --concurrency 20 --sort expiry --json \
  | jpick -r '.results[] | "\(.validity.days_to_expiry)d  \(.subject)"'

# Fail a CI job if anything expires within 14 days (exit 3) or worse
certinspect --input fleet.txt --days 14 --quiet || exit 1

# Gate a deploy: fail (exit 8) unless the new cert covers every required name
certinspect --file ./new-cert.pem \
  --expect-san example.com --expect-san www.example.com --expect-san api.example.com

# Check a single node behind a load balancer by IP, validating the vhost
certinspect 10.0.0.5 --servername api.example.com --verify

# Grab just the SHA-256 fingerprint to pin it later
certinspect example.com --json | jpick -r '.results[0].fingerprint_sha256'

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
