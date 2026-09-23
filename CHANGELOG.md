# Changelog

All notable changes to this project are documented in this file. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the
project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.0] - 2026-09-23

### Added

- Adversarial test hardening from the 2026-08 security audit: mid-stream
  reply scenarios (a FOUND is definitive, an OK for an unfinished stream
  fails closed, garbage falls through to the transport error), reply-size
  and client-side size-limit boundary tests (including proof that no
  connection is dialed for oversized input), an oversized-STATS rejection
  test, and a slow-drip reply test pinning the documented no-progress
  deadline semantics. `internal/clamdtest` gains `SetEarlyReply` and
  `Response.DripInterval` to script these behaviors.
- Fuzz targets for the bounded reply readers (`FuzzReadLine`,
  `FuzzReadBlock`) alongside the existing parser fuzz. `make fuzz` and
  the CI short fuzz pass now run all three via `scripts/fuzz.sh`, which
  keeps the parser's original budget, gives each reader its own, and
  fails if a target name no longer resolves (`go test -fuzz` exits 0
  when its pattern matches nothing).

### Changed

- Raise the Go toolchain floor to 1.26.6, which carries the fixes for
  GO-2026-6090 (`crypto/tls`), GO-2026-6089 (`net/http`) and GO-2026-5972
  (`encoding/asn1`). Older local toolchains fetch it automatically via
  `GOTOOLCHAIN=auto`.
- CI hardening: every GitHub Action is now pinned to a release commit SHA
  (kept current by Dependabot), checkout no longer persists credentials
  into the workspace (no job runs authenticated git commands), and
  govulncheck is pinned to a release version in CI and the Makefile
  instead of `@latest` (the vulnerability database is still fetched live
  at scan time).
- CodeRabbit is retired. Its review contract now lives in the Review
  checklist in AGENTS.md, and every PR gets an independent review against
  it before merging. The workflow checks CodeRabbit used to run now run in
  the required `lint` job: gitleaks over the whole git history,
  actionlint (both also in `make lint`) and zizmor. A separate
  `zizmor-sarif` job, the only one with `security-events: write`, also
  uploads the zizmor audit to code scanning; it does not gate, since
  zizmor exits 0 with SARIF output. YAML and Markdown style linting is
  dropped. Dependabot now waits 7 days before proposing a new version
  (security updates are not delayed).
- Reply classification is stricter: a clean verdict is now produced only
  by the exact reply lines `stream: OK` or `OK` (ADR-0005). Previously
  any `<prefix>: OK` whose prefix contained "stream"
  (case-insensitively) was accepted — including `instream (local): OK`,
  a form no released clamd has ever sent. Such replies now fail closed
  as a `ProtocolError`.
- A clean verdict now also requires a complete reply: an INSTREAM `OK`
  that ends at EOF instead of its NUL terminator fails as a
  `ProtocolError` rather than reading as clean — a cut-short detection
  reply could otherwise have looked like one (ADR-0007). clamd always
  NUL-terminates z-form replies, so conforming servers are unaffected.
- `Scan` checks its context before every `Read` on the source, so a
  cancelled scan stops reading a trickling source at once instead of
  after filling a whole chunk, and reports the cancellation. A source
  that fails on its own is still reported with its own error even when
  the context is done by then (net/http cancels the request context
  when a body read fails), so truncations and read timeouts stay
  matchable with `errors.Is`. A `Read` that blocks still cannot be
  interrupted: the `Scan` godoc, README, docs/operations.md and
  SECURITY.md now say so and show how to bound slow sources.
- The README error table lists input errors (a failing or truncated
  reader, an unusable `ScanFile` path), which are never retryable.

### Fixed

- `ScanFile` can no longer block indefinitely when the target path is
  swapped for a FIFO between the type check and the open: on unix the
  scan target is now opened non-blocking, and the existing descriptor
  re-check rejects non-regular files (ADR-0006). Hardening rather than a
  live exposure — the precondition is write access to the scanned
  directory.
- `Scan` no longer treats a source's own `io.ErrUnexpectedEOF` as end of
  input. net/http and mime/multipart report a truncated request body that
  way, so a cut-short upload was streamed to clamd as complete and could
  come back clean; it now fails with the source error and no INSTREAM
  terminator is sent. Only `io.EOF` ends a stream, and an error returned
  together with the bytes that complete a chunk is no longer dropped.
  Input past the client-side limit is still reported as
  `ErrSizeLimitExceeded` when the source fails in the same chunk (e.g.
  `http.MaxBytesReader`). A source that keeps returning `(0, nil)` now
  fails with `io.ErrNoProgress` instead of spinning forever, and one that
  reports an impossible read count fails instead of panicking.
- `examples/httpupload` now sets `http.Server.ReadTimeout`, so a client
  trickling its upload can no longer pin a goroutine and the multipart
  parser's memory indefinitely. It answers `408` when the body times out
  and `400 incomplete upload` when the client disconnects mid-body,
  instead of reporting a missing form field.

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

[Unreleased]: https://github.com/PyYoshi/go-clamav/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/PyYoshi/go-clamav/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/PyYoshi/go-clamav/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/PyYoshi/go-clamav/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/PyYoshi/go-clamav/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/PyYoshi/go-clamav/releases/tag/v0.1.0
