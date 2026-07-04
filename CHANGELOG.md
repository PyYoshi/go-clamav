# Changelog

All notable changes to this project are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/PyYoshi/go-clamav/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/PyYoshi/go-clamav/releases/tag/v0.1.0
