# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `--require-must-staple`: opt-in policy check that fails (exit code 9) when
  the certificate lacks the OCSP Must-Staple extension (RFC 7633 TLS Feature
  `status_request`). Whether the extension is present is also reported as the
  `must_staple` field (`--json`) and a `Must-Staple` row in the human output.
- `--min-tls-version`: opt-in policy check that fails (exit code 9) when the
  connection negotiates a TLS version older than the given floor (e.g.
  `TLSv1.2`). Host targets only, as it needs a live handshake.
- `--field NAME`: print only the selected field(s), one tab-separated line per
  target (repeatable; `target` exposes the inspected host). Handy for scripting
  without piping `--json` through a JSON tool.
- `--exit-zero`: always exit with code 0, even on problems or fetch errors, for
  report-only dashboards/CI that read the output rather than the exit code.

## [1.5.0] - 2026-07-21

### Added

- New `NOT YET VALID` status (exit code 4) for certificates whose validity
  period starts in the future, so a not-yet-usable certificate is no longer
  misreported as `VALID`. The `--summary` tally counts it separately as
  `not-yet-valid`.
- `--file -` reads the certificate from standard input, so a certificate can
  be piped in (e.g. `openssl ... | certinspect --file -`).
- `--require-sct`: opt-in policy check that fails (exit code 9) when the
  certificate embeds no Signed Certificate Timestamps (Certificate
  Transparency). Only the SCTs embedded in the certificate are checked, not
  those delivered over the TLS handshake or OCSP. The number of embedded SCTs
  is also reported as the `sct_count` field (`--json`) and an `SCTs` row in
  the human output.

## [1.4.1] - 2026-07-20

### Fixed

- `--json` output no longer escapes non-ASCII characters as `\uXXXX`
  (`json.dumps` now uses `ensure_ascii=False`), so subjects/issuers with
  accented or non-Latin characters are emitted as readable UTF-8 and can be
  consumed by tools that don't decode `\u` escapes.

## [1.4.0] - 2026-07-16

### Added

- `--cab-forum`: a date-aware shorthand for `--not-after-max` that enforces the
  CA/Browser Forum maximum TLS validity in effect on the current date (398 days
  today, then 200 on 2026-03-15, 100 on 2027-03-15 and 47 on 2029-03-15, per
  ballot SC-081). Fails with exit code 9 like the other policy checks and is
  mutually exclusive with `--not-after-max`.

## [1.3.0] - 2026-07-16

### Added

- JSON output now includes a `status` field (`VALID`, `EXPIRING`, `CRITICAL`,
  `EXPIRED` or `INVALID DATES`) mirroring the human report's status line and
  honoring `--days` / `--critical-days`, so a JSON consumer gets the verdict
  directly instead of re-deriving it from the dates.

## [1.2.0] - 2026-07-16

### Added

- Opt-in policy checks that fail with a new exit code 9 without changing the
  default behavior: `--not-after-max N` (fail when the total validity exceeds N
  days, e.g. 398 for the CA/Browser Forum maximum), `--min-key-size N` (fail
  when the public key is below N bits) and `--fail-weak` (promote the existing
  weak-crypto warnings — small key, SHA-1/MD5 signature — to a hard failure).
  The human report gains a `Policy` line and the `--summary` tally a `policy`
  category.
- Prometheus exporter: three further gauges emitted only for the targets whose
  check actually ran — `certinspect_hostname_match` (host targets) and, with
  `--verify`, `certinspect_chain_trusted` and `certinspect_cert_revoked` (the
  latter only when OCSP/CRL gives a definitive answer). Lets alerting rules
  target chain, hostname and revocation problems directly instead of parsing
  the report text.

### Fixed

- `--summary` no longer raises a `KeyError` when a target fails an
  `--expect-san` assertion (exit code 8); such targets are now tallied under a
  new `san-mismatch` category.

## [1.1.0] - 2026-07-13

### Added

- `--servername NAME`: override the SNI hostname sent in the TLS handshake
  (host targets only). Lets you reach a specific backend by IP or DNS name
  while presenting the virtual host a load balancer routes on; the hostname
  match is then checked against `NAME` instead of the connection target.
- `--expect-san NAME`: assert that the certificate's SAN covers `NAME`
  (wildcards honored) and exit with code 8 when any expected name is missing.
  Repeat the flag to require several names; works for both host and `--file`
  targets. The report shows an `Expected SAN` line and a per-name warning.

## [1.0.4] - 2026-06-26

### Fixed

- Revocation: OCSP checks now soft-fail when the responder returns a
  BasicOCSPResponse the strict ASN.1 parser rejects (seen with DigiCert/GitHub).
  Instead of raising and aborting the whole inspection, the check degrades to
  `UNAVAILABLE` and lets the CRL fallback take over.

## [1.0.3] - 2026-06-26

### Added

- Project logo (`docs/logo.svg`) shown in the README header.

### Changed

- README: centered hero with logo, a dot-separated subtitle and a navigation
  link bar, and a scannable "Features" table replacing the old bullet lists.

## [1.0.2] - 2026-06-26

### Changed

- README: reworked the hero with a sharper tagline and pitch, added a "Recipes"
  section of power-user one-liners (jq, CI gating, Prometheus, cron), and fixed
  the stale `--version` example output.

## [1.0.1] - 2026-06-26

### Added

- README: per-option examples with real output, and a reproducible
  `--concurrency` benchmark showing the parallel speedup.

### Fixed

- Publish workflow: skip the PyPI upload when the version already exists, so
  re-pushing a tag no longer fails the release pipeline.

## [1.0.0] - 2026-06-26

### Added

- CRL revocation fallback: when OCSP is unavailable, `--verify` now downloads
  the certificate's CRL distribution points (verified against the issuer) to
  determine the revocation status.
- Warn when an intermediate or root certificate in the chain is already expired
  or expires within the `--days` window (uses the verified chain with
  `--verify`, otherwise the chain presented by the server).

## [0.11.0] - 2026-06-26

### Added

- `--cafile`/`--capath` to verify the certificate chain against a private or
  internal CA bundle/directory instead of the system trust store (requires
  `--verify`).

## [0.10.0] - 2026-06-26

### Added

- `--critical-days` two-tier expiry threshold: certificates expiring within the
  critical window are reported as `CRITICAL` (exit code 4), separately from the
  `EXPIRING` warning window (`--days`).

## [0.9.0] - 2026-06-26

### Added

- `--summary` tally line summarizing results by status (valid, expiring,
  expired, mismatch, untrusted, pin-mismatch) plus error count.
- `--sort` to order batch output by `host` or `expiry`.

### Changed

- CI now auto-creates a GitHub Release on tag push.

### Removed

- Obsolete `scadenze.csv` file.

## [0.8.0] - 2026-06-26

### Added

- `--csv` spreadsheet-friendly output with a leaner, comma-free column set.
- `--csv-delimiter` to choose the field separator (e.g. `;` for spreadsheets in
  some locales).
- `--max-days` filter to show only certificates expiring within N days.

## [0.7.0] - 2026-06-26

### Added

- `--concurrency` for parallel batch inspection.

## [0.6.0] - 2026-06-26

### Added

- `--starttls` to inspect certificates behind STARTTLS (e.g. SMTP, IMAP, POP3).

## [0.5.0] - 2026-06-26

### Added

- `--exporter` for Nagios and Prometheus monitoring output.

### Changed

- Reworked the README feature paragraph into a checklist.

## [0.4.1] - 2026-06-25

### Added

- Accept full URLs and `host:port` strings as targets.

## [0.4.0] - 2026-06-25

### Added

- `--chain` to print the full certificate chain.
- `--pin` to assert an expected certificate fingerprint.
- `--input` to read targets from a file.
- CI workflow running tests and ruff on every push and pull request.
- Trusted-publishing workflow for tagged releases.
- CI, PyPI and Python version badges in the README.

## [0.3.1] - 2026-06-25

### Fixed

- Source the OCSP issuer from the verified TLS chain.

## [0.3.0] - 2026-06-25

### Added

- `--verify` for certificate chain trust validation and OCSP revocation checking.

## [0.2.0] - 2026-06-25

### Added

- TLS connection info (protocol version, cipher), key usage details and
  additional CLI flags.

### Changed

- Rewrote the README in English with updated options and exit codes.

## [0.1.0] - 2026-06-25

### Added

- Initial release: core TLS certificate inspector with human-readable and JSON
  output.

[Unreleased]: https://github.com/mangrisano/certinspect/compare/v1.5.0...HEAD
[1.5.0]: https://github.com/mangrisano/certinspect/compare/v1.4.1...v1.5.0
[1.4.1]: https://github.com/mangrisano/certinspect/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/mangrisano/certinspect/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/mangrisano/certinspect/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/mangrisano/certinspect/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/mangrisano/certinspect/compare/v1.0.4...v1.1.0
[1.0.4]: https://github.com/mangrisano/certinspect/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/mangrisano/certinspect/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/mangrisano/certinspect/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/mangrisano/certinspect/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/mangrisano/certinspect/compare/v0.11.0...v1.0.0
[0.11.0]: https://github.com/mangrisano/certinspect/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/mangrisano/certinspect/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/mangrisano/certinspect/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/mangrisano/certinspect/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/mangrisano/certinspect/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/mangrisano/certinspect/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/mangrisano/certinspect/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/mangrisano/certinspect/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/mangrisano/certinspect/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/mangrisano/certinspect/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/mangrisano/certinspect/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/mangrisano/certinspect/releases/tag/v0.2.0
