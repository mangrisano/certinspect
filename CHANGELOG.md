# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/mangrisano/certinspect/compare/v0.11.0...HEAD
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
