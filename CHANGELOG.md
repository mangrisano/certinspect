# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.4.4] - 2026-09-25

### Fixed

- A host is no longer reported as trusted on the strength of a different
  certificate. The chain is verified over a second TLS connection, and nothing
  checked that it saw the same certificate as the inspection; behind a load
  balancer with mismatched backends an expired or foreign certificate could
  show `chain_trusted: true`. When the two differ, the chain is now reported
  as not trusted ("the server presented a different certificate on the
  verification handshake", exit code 6).

## [2.4.3] - 2026-09-25

### Fixed

- Certificate-supplied OCSP, CRL and CA-Issuer URLs (and the CT-log queries)
  can no longer reach an internal address through DNS rebinding. The address
  check resolved the name, then the HTTP client resolved it again to connect,
  so a name server answering first with a public IP and then with `127.0.0.1`
  or `169.254.169.254` got the request through. The connection now goes to the
  address that was checked, on every redirect too. Requests sent through a
  proxy are still checked by name only, since the proxy resolves it.
- A server sending one byte at a time can no longer stall a run. The timeouts
  applied to each single read, so a reply dripped just under `--read-timeout`
  never ended: STARTTLS replies and the proxy `CONNECT` answer now have to
  arrive in full within the read (or connect) timeout, and OCSP, CRL,
  CA-Issuer and CT-log downloads within 60 seconds overall. The TLS handshake
  was already bounded.
- A malformed HTTP response from an OCSP, CRL or CA-Issuer server is now a
  soft failure like any other unusable answer, instead of an unhandled
  exception that aborted the whole batch.

## [2.4.2] - 2026-09-25

### Changed

- Internal refactor, no change in behavior or output. The `--state-file`
  handling moved to a new `state` module, the `--discover-only` inventory is
  rendered by the formatter, `main()` and the chain/revocation checks were
  split into smaller functions, and revocation statuses and inspection results
  are now typed (`RevocationStatus`, `InspectionResult`).

## [2.4.1] - 2026-09-25

### Fixed

- The `--csv` `common_name` and `issuer` columns now parse the distinguished
  name instead of splitting it on commas. A Common Name containing a comma
  (`ACME, Inc`) was truncated to `ACME\`, and a fake `CN=` hidden after an
  escaped comma in another attribute could make the `issuer` column show a CA
  that did not issue the certificate.
- The `--exporter nagios` perfdata thresholds now use the `N:` range form
  (`days=44;30:;7:`), meaning "alert below N". The bare `30;7` meant "alert
  above N" under the Monitoring Plugins range rules, so graphers and tools that
  evaluate perfdata saw a healthy certificate as CRITICAL and one about to
  expire as OK. Without `--critical-days` the critical threshold is `0:`
  (expired), matching the plugin's own state.
- `--state-file` no longer forgets a target that could not be reached: it
  keeps its last known status. Before, the file was rewritten with only the
  targets inspected successfully, so after a transient outage the host came
  back as "seen for the first time" and `--only-changed` reported a change
  that never happened.
- `--export` with more than one target (hosts, several `--file`, or a
  `--discover` that finds several hosts) is now a usage error (exit 2). Every
  target used to overwrite the same file, so only the last certificate was
  saved and the others were lost without a warning.

## [2.4.0] - 2026-09-25

### Added

- A `key_type` field (`RSA`, `EC`, `DSA`, `Ed25519`, `Ed448`) in the JSON
  output (`key.type` in schema 2) and next to the key size in the text output.

### Fixed

- A certificate with an Ed25519 or Ed448 key no longer crashes the whole run
  with a traceback; its `key_size` is reported as `null` (`n/a` in text).
- `--min-key-size` (and the `standard`/`strict` profiles) no longer fails every
  EC certificate: the minimum now applies to RSA and DSA keys only, since an EC
  key's bit length is not on the RSA scale.
- Offline `--file` verification no longer reports a valid chain as untrusted
  when the leaf's first SAN is a wildcard (e.g. `*.example.com`).
- A host target on a non-default port is now labelled `host:port` (e.g.
  `a.com:8443`, `[::1]:8443`) in every output, the `--state-file` and the
  Prometheus `target` label. Before, the port was dropped, so two services on
  the same host collided: duplicate Prometheus series (rejected by the
  textfile collector) and one state overwriting the other. Targets on the
  default port keep their bare host label, and an unreachable target now gets
  the same label as a reachable one.
- When a certificate (or a batch) has several problems, the exit code is now
  the most severe one, as documented, instead of whichever check ran last or
  the highest number. An expired certificate with a weak key exits 4, not 9; a
  revoked one with a pin or SAN mismatch exits 6, not 7/8; and an unreachable
  host (1) now outranks SAN, policy and expiry warnings. The order is listed
  in the README's "Exit codes" section.

### Security

- The SSRF guard on certificate-supplied OCSP, CRL and CA-Issuer URLs (and the
  crt.sh query) now also checks every HTTP redirect. Previously only the first
  URL was screened, so a public host could redirect certinspect to loopback or
  the cloud metadata endpoint (`169.254.169.254`). Redirects are also limited
  to http/https and to 5 hops.
- A hostile server can no longer stall or exhaust the memory of a `--starttls`
  inspection: the plaintext negotiation now rejects a reply line longer than
  8 KB and a reply of more than 100 lines (a line with no newline, an endless
  `250-` continuation or endless untagged IMAP lines used to be read forever).
- The issuer certificate used to check OCSP and CRL signatures must now have
  signed the inspected certificate. An issuer downloaded from the AIA "CA
  Issuers" URL (plain HTTP, so replaceable on the network) was accepted as-is,
  letting an attacker supply their own "issuer" and sign revocation answers.
- OCSP responses are now authenticated before their status is believed: the
  response must be about the requested certificate (serial and issuer hashes)
  and be validly signed by the issuer or by a delegated responder issued by it
  with the OCSP Signing EKU (RFC 6960). A forged answer, or a genuine GOOD for
  another certificate of the same CA, used to be accepted; it now degrades to
  UNAVAILABLE and the CRL fallback runs. Unauthenticated REVOKED answers are
  ignored the same way.
- CRLs are now trusted only when their signature is verified against the
  issuer (without a known issuer none is used), their issuer name matches the
  certificate's, and their scope can cover it (RFC 5280). A CRL limited to CA
  certificates, attribute certificates or indirect entries, or carrying an
  unknown critical extension, is ignored; a partial CRL (a delta CRL or one
  limited to some revocation reasons) can prove REVOKED but no longer GOOD.

## [2.3.3] - 2026-09-22

### Changed

- Internal refactor only, with no change to behavior, output or exit codes:
  renamed `config.load_config`/`DEFAULT_CONFIG_PATH`, `render.render`/
  `load_state`/`save_state` and `httpfetch.fetch` to drop their leading
  underscore, since they are imported across modules and the underscore
  wrongly signalled module-private.

## [2.3.2] - 2026-09-20

### Changed

- Internal refactor only, with no change to behavior, output or exit codes:
  the validity status is now a `Status` enum (one authoritative definition of
  the status set), and the `fetch` module was split by concern into `fetch`
  (TLS connection and handshake), `revocation` (OCSP/CRL) and `httpfetch` (the
  SSRF-guarded HTTP client shared with Certificate Transparency discovery).

## [2.3.1] - 2026-09-20

### Changed

- Internal refactor only, with no change to behavior, output or exit codes:
  the oversized `cli` module was split into focused modules (argument parser,
  shell completion, config loading, result rendering), the process exit codes
  were centralized in an `ExitCode` enum, the per-check inspection logic was
  extracted into named helpers, and a `CertificateInfo` typed shape now
  documents the analyzed-certificate data.

## [2.3.0] - 2026-09-20

### Added

- `--config PATH` loads default option values from a TOML file (auto-discovered
  at `~/.config/certinspect/config.toml` when the flag is omitted); an explicit
  command-line flag always overrides it.
- `--file` is now repeatable, inspecting several local certificate files in one
  run (each reported separately); it can no longer be combined with host
  targets.
- `--discover` and `--discover-only` query several domains concurrently
  (governed by `--concurrency`) instead of one at a time.
- `--state-file PATH` persists each host's status across runs and
  `--only-changed` shows only the targets whose status changed since the
  previous run, for low-noise recurring monitoring.
- `--print-completion {bash,zsh}` prints a shell completion script generated
  from the live argument parser.
- A `Dockerfile` builds a minimal container image running `certinspect`.

## [2.2.0] - 2026-09-03

### Added

- `--discover DOMAIN` enumerates hostnames from Certificate Transparency logs
  (crt.sh) for a domain and inspects each one, surfacing forgotten or shadow
  certificates. Repeat the flag for several domains; host targets only.
- `--discover-only` lists the Certificate Transparency inventory for the
  `--discover` domain(s) — expiry, issuer and hostnames, tab-separated and
  soonest expiry first, wildcards included — without connecting to any host.
  Useful for a fast audit or spotting a certificate from an unexpected CA.
- `--discover-only` now honors `--json`, emitting the CT inventory as a JSON
  array (one object per certificate: domain, hostnames, issuer, validity).
- `--expect-issuer SUBSTRING` (repeatable) turns the `--discover-only` inventory
  into a mis-issuance check: any certificate whose issuer matches none of the
  substrings (case-insensitive) is flagged and the command exits with code 9.
- `--discover-only` also honors `--csv` (with `--csv-delimiter`), writing the CT
  inventory as a spreadsheet-friendly table.
- `--discover-timeout N` sets the timeout for the crt.sh query separately from
  `--timeout` (default 30 seconds), since a log search can be slower than a TLS
  handshake.

## [2.1.1] - 2026-08-15

### Fixed

- Package metadata now includes the author email address, so PyPI and package
  tools expose `Michele Angrisano <michele.angrisano@gmail.com>` instead of an
  empty author-email field.

## [2.1.0] - 2026-08-15

### Added

- `--require-revocation-check`, an opt-in policy check for strict CI/audit use
  cases that fails with exit code 9 unless OCSP or CRL returns a definitive
  `GOOD` verdict. The default remains browser-like soft-fail behavior.

### Fixed

- CRL fallback now checks the CRL `lastUpdate`/`nextUpdate` freshness before
  treating an absent serial number as a `GOOD` revocation verdict; stale or
  not-yet-valid CRLs soft-fail as `UNAVAILABLE`, while an explicit revoked
  serial still reports `REVOKED`.

## [2.0.0] - 2026-08-03

This is a major release with **breaking changes** to the default JSON output,
the verification default and the supported Python versions. See the migration
notes under each item.

### Changed

- **Verification is now on by default.** A plain host inspection opens a
  verified handshake and queries OCSP/CRL, and `--file` validates the bundled
  chain offline — the `Chain trusted`/`Revocation` rows (and exit code 6 on an
  untrusted or revoked certificate) now appear without `--verify`. Pass
  `--no-verify` to restore the old inspect-only behavior. `--verify` is kept as
  an explicit no-op. `--cafile`/`--capath` are now incompatible with
  `--no-verify` (previously they required `--verify`).
- **`--json` emits a new, versioned schema (version 2) by default.** The output
  is now an envelope — `{"schema_version": 2, "certinspect_version": ...,
"results": [...]}` — where each result carries the inspected `target`, groups
  related fields under `validity`, `key`, `connection`, `chain`, `revocation`
  and `policy`, renders dates as ISO 8601 (`T` separator) and stringifies the
  serial number to avoid precision loss. Pass `--schema 1` to keep the legacy
  flat array (unchanged from 1.x) while you migrate.
- **Dropped Python 3.10 and 3.11.** The minimum supported version is now
  Python 3.12.

### Added

- `--no-verify` flag to skip chain verification (and revocation for hosts).
- `--schema {1,2}` flag to select the `--json` schema version (default `2`).

## [1.13.0] - 2026-08-03

### Added

- `--file --verify` now validates the certificate chain **offline**: when the
  file is a bundle carrying the leaf, its intermediates and (optionally) the
  root, the leaf is verified against the system trust store — or
  `--cafile`/`--capath` for an internal PKI — using the bundled intermediates,
  exactly like `openssl verify`. Sets `chain_trusted` (exit code 6 on failure)
  and, when it fails, the same `chain_diagnosis` hint as host verification.
  Revocation is not queried offline.
- `--file --chain` now lists every certificate in the bundle instead of only
  the leaf.

## [1.12.0] - 2026-07-31

### Added

- Prometheus exporter: a `certinspect_policy_ok` gauge, emitted only when policy
  checks are requested, reporting `1` when a target passed every requested
  policy check and `0` when it violated at least one — so you can alert on
  policy breaches (exit code 9) without parsing text.

### Changed

- Signature-algorithm and extended-key-usage names are now resolved through a
  stable OID → name table instead of cryptography's private, undocumented
  `ObjectIdentifier._name` attribute, which drifted across library versions and
  even returned `"Unknown OID"` for some well-known OIDs. Output for common
  certificates is unchanged; unmapped OIDs now fall back to their dotted string.

## [1.11.0] - 2026-07-30

### Added

- Separate connect and read timeouts (`--connect-timeout`, `--read-timeout`,
  both defaulting to `--timeout`) so a dead host fails fast while a slow
  handshake is still allowed, and `--retries N` to retry transient connection
  failures (timeouts, refused/reset connections, DNS errors) instead of
  reporting a false failure. `get_server_cert`/`verify_chain` accept a
  requests-style `(connect, read)` timeout tuple.

## [1.10.0] - 2026-07-30

### Added

- Chain diagnosis: when `--verify` fails, certinspect now classifies _why_ into
  a `chain_diagnosis` (`code` + human `detail`) instead of only a raw OpenSSL
  error. Codes: `INCOMPLETE_CHAIN` (server didn't send the intermediate; the
  AIA "CA Issuers" URL is shown), `CHAIN_MISMATCH` (the sent intermediates do
  not sign the leaf), `UNTRUSTED_ROOT` (chain complete but the anchor isn't
  trusted — suggests `--cafile`), and `EXPIRED_IN_CHAIN`. The diagnosis uses the
  chain the server presents, exposed by Python 3.13+.

## [1.9.2] - 2026-07-29

### Fixed

- `verify_chain` now validates chain trust independently of the hostname. It
  previously inherited `check_hostname=True`, so a certificate with a valid
  chain but a mismatched hostname was reported as `chain_trusted=false` (with a
  misleading "Hostname mismatch" chain error) even though the chain was sound.
  The hostname is already reported separately as `hostname_match` (exit code 5),
  so `chain_trusted` now reflects the chain alone.

## [1.9.1] - 2026-07-29

### Changed

- Republish of 1.9.0, which was tagged but never reached PyPI because of a CI
  issue. Pins the ruff lint rule set (`[tool.ruff.lint] select`) to the classic
  default so the build stays reproducible regardless of the ruff version CI
  installs. Same features as 1.9.0 — the new `--profile` option and the
  revocation/SSRF hardening listed below.

## [1.9.0] - 2026-07-29

### Added

- `--profile {lenient,standard,strict}`: apply a named bundle of the opt-in
  policy checks (exit code 9) in one go, so a common hardening level is a single
  flag away. The names are a plain intensity ladder (each tier a superset of the
  one below), not an official standard, and passing a profile is not a
  compliance attestation. `lenient` requires TLS >= 1.2 and fails on weak
  crypto; `standard` adds a 2048-bit minimum key; `strict` requires TLS >= 1.3,
  a 2048-bit key, weak-crypto failure, embedded Certificate Transparency SCTs
  and the CA/Browser Forum validity cap. Any explicit policy flag overrides the
  profile, and the profile's TLS-version requirement is skipped for `--file`
  targets (no live handshake).

### Security

- Revocation lookups now refuse to follow an OCSP, CRL or CA-Issuer URL taken
  from the certificate when it resolves to a loopback, link-local (the cloud
  metadata endpoint `169.254.169.254`), unspecified, multicast or reserved
  address, closing a server-side request forgery (SSRF) vector. Private RFC1918
  ranges stay allowed so revocation keeps working behind an internal PKI. The
  downloaded response is also size-capped so a malicious certificate cannot
  point the fetch at an unbounded download.
- OCSP responses whose validity window has lapsed (a `nextUpdate` already in
  the past) or has not yet begun are now treated as `UNAVAILABLE` instead of a
  trusted `GOOD`, so a replayed stale response can no longer mask a later
  revocation. The CRL fallback still applies.

## [1.8.0] - 2026-07-21

### Added

- The standard proxy environment variables (`HTTPS_PROXY`/`HTTP_PROXY`, and
  the system proxy settings on macOS/Windows) are now honoured automatically
  when no `--proxy` is given, respecting `NO_PROXY`, the same way curl behaves.
  A new `--no-proxy` flag forces a direct connection, and `--proxy` still
  overrides everything.

## [1.7.0] - 2026-07-21

### Added

- IP-address Subject Alternative Names are now included in the `san` field
  alongside DNS names, so certificates issued for IPs (common for cloud load
  balancers and internal services) are reported correctly and `--expect-san`
  can assert an IP is covered.
- `--client-cert`/`--client-key`: present a client certificate for mutual-TLS
  (mTLS) endpoints (host targets only).
- `--proxy URL`: tunnel the connection through an HTTP CONNECT proxy (e.g.
  `http://proxy:8080`, with optional `user:pass@`), so hosts reachable only
  through a corporate/cloud egress proxy can be inspected. Applies to the
  certificate fetch and `--verify` (host targets only).

## [1.6.0] - 2026-07-21

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
  output.3...HEAD
[Unreleased]: https://github.com/mangrisano/certinspect/compare/v2.4.4...HEAD
[2.4.4]: https://github.com/mangrisano/certinspect/compare/v2.4.3...v2.4.4

[Unreleased]: https://github.com/mangrisano/certinspect/compare/v2.4.2...HEAD
[2.4.2]: https://github.com/mangrisano/certinspect/compare/v2.4.1...v2.4.2
[2.4.1]: https://github.com/mangrisano/certinspect/compare/v2.4.0...v2.4.1
[2.4.0]: https://github.com/mangrisano/certinspect/compare/v2.3.3...v2.4.0
[2.3.3]: https://github.com/mangrisano/certinspect/compare/v2.3.2...v2.3.3
[2.3.2]: https://github.com/mangrisano/certinspect/compare/v2.3.1...v2.3.2
[2.3.1]: https://github.com/mangrisano/certinspect/compare/v2.3.0...v2.3.1
[2.3.0]: https://github.com/mangrisano/certinspect/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/mangrisano/certinspect/compare/v2.1.1...v2.2.0
[2.1.1]: https://github.com/mangrisano/certinspect/compare/v2.1.0...v2.1.1
[2.1.0]: https://github.com/mangrisano/certinspect/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/mangrisano/certinspect/compare/v1.13.0...v2.0.0
[1.13.0]: https://github.com/mangrisano/certinspect/compare/v1.12.0...v1.13.0
[1.12.0]: https://github.com/mangrisano/certinspect/compare/v1.11.0...v1.12.0
[1.11.0]: https://github.com/mangrisano/certinspect/compare/v1.10.0...v1.11.0
[1.10.0]: https://github.com/mangrisano/certinspect/compare/v1.9.2...v1.10.0
[1.9.2]: https://github.com/mangrisano/certinspect/compare/v1.9.1...v1.9.2
[1.9.1]: https://github.com/mangrisano/certinspect/compare/v1.9.0...v1.9.1
[1.9.0]: https://github.com/mangrisano/certinspect/compare/v1.8.0...v1.9.0
[1.8.0]: https://github.com/mangrisano/certinspect/compare/v1.7.0...v1.8.0
[1.7.0]: https://github.com/mangrisano/certinspect/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/mangrisano/certinspect/compare/v1.5.0...v1.6.0
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
