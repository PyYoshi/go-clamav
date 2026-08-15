# Changelog

All notable changes to this project are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- Raise the Go toolchain floor to 1.26.6, which carries the fixes for
  GO-2026-6090 (`crypto/tls`), GO-2026-6089 (`net/http`) and GO-2026-5972
  (`encoding/asn1`). Older local toolchains fetch it automatically via
  `GOTOOLCHAIN=auto`.

## [0.2.2] - 2026-07-30

### Added

- Integration coverage for clamd's heuristic alert behavior, verified
  against ClamAV 1.4.5 and 1.5.3: a second alert-enabled clamd service
  (`docker/clamd/clamd-strict.conf`, `AlertEncryptedArchive`,
  `AlertEncryptedDoc`, `AlertExceedsMax`, `AlertBrokenMedia`) and a
  `TestIntegrationStrict` suite asserting that a real signature outranks
  the encrypted-entry heuristic in mixed archives (with the default
  `HeuristicScanPrecedence no`), and that encrypted archives, broken
  media and exceeded limits surface as `Heuristics.*` detections rather
  than silent `OK` replies. The default-config suite now also documents
  that encrypted archives scan clean while the alerts are off.
- `internal/clamdtest`: in-memory builders for the samples behind those
  tests — a hand-rolled ZIP writer with PKWARE "ZipCrypto" encryption
  (`BuildZip`), nested archives (`NestedZip`), and broken-media samples
  (`TruncatedPNG`, `HeaderOnlyJPEG`). Standard library only; EICAR-bearing
  archives are assembled at run time and never written to disk.

## [0.2.1] - 2026-07-24

### Changed

- Raise the Go toolchain floor to 1.26.5, which carries the fix for
  GO-2026-5856 (Encrypted Client Hello privacy leak in `crypto/tls`).
  Older local toolchains fetch it automatically via `GOTOOLCHAIN=auto`.

## [0.2.0] - 2026-07-05

### Changed

- Require Go 1.26.4+ as the toolchain floor (includes current stdlib
  security fixes; older local toolchains fetch it automatically via
  GOTOOLCHAIN=auto).
- CI now tests against ClamAV 1.4 LTS (the recommended default, supported
  until 2027-08-15) and 1.5 (current regular release). ClamAV 1.0 was
  dropped from the matrix at its EOL (2025-11-28).
- `make lint` now runs golangci-lint v2 with a security-heavy
  configuration (gosec with all rules, bidichk, strict errcheck,
  exhaustive verdict switches, and more) plus govulncheck; the standalone
  staticcheck invocation was removed (bundled in golangci-lint).

### Added

- `make format`: gofumpt + gci formatting via `golangci-lint fmt`.
- Dependabot configuration (gomod, GitHub Actions, compose images).
- `examples/mockscan`: a compiled, tested example of mocking the client in
  consumer tests (consumer-defined interface idiom, fail-closed mock
  rules), plus ADR-0004 recording the decision not to export a scanner
  interface.
- Development harness for human and AI contributors: the AGENTS.md
  contract (invariants, Definition of Done, design gate), CONTRIBUTING.md,
  an ADR template plus backfilled ADRs (0002 fail-closed error model,
  0003 zero-dependency policy), a pull-request template, shared guard
  scripts (`scripts/`), repository git hooks (`githooks/`, enabled via
  `make setup`), Claude Code hooks and skills (`.claude/`), new
  `make verify` / `make setup` targets, and CI guards for the assembled
  EICAR string and the zero-dependency policy.

## [0.1.0] - 2026-07-04

### Added

- Pure-Go clamd client over `unix://` / `tcp://` sockets (stdlib only,
  `CGO_ENABLED=0`).
- `Scan`, `ScanBytes`, `ScanFile` using the INSTREAM command exclusively;
  fail-closed `ScanResult`/`Verdict` model where any error implies the zero
  result (`VerdictUnknown`).
- Error taxonomy: `ErrSizeLimitExceeded`, `ClamdError`, `ProtocolError`,
  `ConnectionError`, and `IsRetryable` for retry classification.
- Client-side stream size limit (default 25 MiB, `NoSizeLimit` to disable),
  bounded reply reads, per-operation I/O timeouts, full `context.Context`
  integration, and an optional scan concurrency cap
  (`WithMaxConcurrentScans`).
- Admin commands: `Ping`, `Version`, `Stats`, `Reload`.
- Recovery of clamd's buffered `INSTREAM size limit exceeded. ERROR` reply
  when the stream write fails mid-flight.
- Dockerized integration environment (EICAR-only hex signature database,
  unix + tcp), unit suite with a scriptable fake clamd, reply-parser fuzz
  harness, GitHub Actions CI with a clamd version matrix.
- Documentation: fail-closed contract (README.md / README.ja.md),
  SECURITY.md threat model, ADR-0001, operations guide, runnable examples
  (`basicscan`, `httpupload`).

[Unreleased]: https://github.com/PyYoshi/go-clamav/compare/v0.2.2...HEAD
[0.2.2]: https://github.com/PyYoshi/go-clamav/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/PyYoshi/go-clamav/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/PyYoshi/go-clamav/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/PyYoshi/go-clamav/releases/tag/v0.1.0
