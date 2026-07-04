# ADR-0001: clamd socket client over libclamav (cgo)

- Status: Accepted
- Date: 2026-07-04

## Context

go-clamav exists to scan untrusted user uploads asynchronously before they
are accepted (the same shape as GoogleCloudPlatform/docker-clamav-malware-
scanner: an upload lands, a worker scans it, the file is routed to a clean
or quarantine destination). Two integration strategies were evaluated:

1. **libclamav via cgo** — link the ClamAV engine into the Go process.
2. **clamd socket client** — talk to the ClamAV daemon over its
   unix/tcp socket protocol using the INSTREAM command, in pure Go.

## Decision

Implement a **pure-Go clamd socket client**, INSTREAM only. libclamav is
not used, and path-based commands (SCAN/CONTSCAN/MULTISCAN) are not used.

## Rationale

1. **Licensing (decisive).** libclamav is GPLv2-only. Linking it via cgo
   raises derivative-work questions for every downstream consumer of this
   library. Talking to clamd over a socket is a clean process boundary, so
   this library can be MIT-licensed without imposing GPL obligations on
   its users.
2. **Memory and startup.** libclamav loads the signature databases
   in-process: >1 GiB RSS and tens of seconds of startup per process.
   Upload-verification workers scale horizontally; loading a database copy
   per worker is prohibitive. With clamd the database lives in exactly one
   process (a sidecar or shared service), which is also the reference
   architecture of the GCP malware-scanner.
3. **Build and distribution.** cgo drags a C toolchain and libclamav dev
   headers into every consumer build and breaks trivial cross-compilation.
   The socket client is stdlib-only and builds with CGO_ENABLED=0.
4. **Fault isolation.** A crash or memory-safety bug in the scanning
   engine kills clamd, not the application. Under the fail-closed contract
   an unreachable scanner degrades to "reject uploads", which is the safe
   direction.
5. **Operational separation.** Signature updates (freshclam), engine
   limits (clamd.conf), and scaling are operated on the clamd deployment
   without touching application code.

### Why INSTREAM only

Path-based commands require clamd and the application to share a
filesystem view, leak upload paths into another trust domain, and are
open to time-of-check/time-of-use races on the path. INSTREAM streams the
bytes over the socket: clamd never needs access to the file, and what is
scanned is exactly what was read.

## Considered objections

- **The reply grammar is informal.** clamd replies are de-facto stable but
  unversioned; older versions used different prefixes ("instream (local):"
  vs "stream:"). Mitigated with a prefix-agnostic, suffix-based parser
  (FOUND / ERROR / OK), fuzzing, and a CI matrix across clamd versions.
- **Bytes cross the socket twice** (source → app → clamd). True, and
  irrelevant in practice over unix sockets / loopback; the reference GCP
  architecture has the same property.
- **Per-scan engine settings are impossible.** Engine limits are fixed in
  clamd.conf. For the single use case (upload verification) this is a
  feature: limits are enforced in one audited place.
- **Existing Go clients** (e.g. dutchcoders/go-clamd) were evaluated:
  no context support, no error taxonomy, fail-open-prone APIs, dormant
  maintenance. A fail-closed design was the point of this library, so a
  fresh implementation was chosen.

## Consequences

- clamd is a hard runtime dependency; deployments must run it (sidecar,
  host daemon, or dedicated service) and operate freshclam.
- clamd unavailability means scans fail (and uploads are rejected) until
  it recovers — accepted, and documented as the fail-closed contract.
- IDSESSION/connection pooling is deliberately out of scope for v1; the
  per-command-connection model matches clamd's own session semantics and
  the internals can adopt pooling later without changing the public API.
