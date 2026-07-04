# Security Policy

go-clamav is itself a security control (malware scanning of untrusted
input), so defects in it can have direct security impact. Please read the
threat model below before reporting.

## Reporting a vulnerability

Please report suspected vulnerabilities privately via
[GitHub Security Advisories](https://github.com/PyYoshi/go-clamav/security/advisories/new)
("Report a vulnerability"). Do not open public issues for security reports.

You can expect an acknowledgement within 7 days. Coordinated disclosure is
appreciated; a fix or mitigation will be published before details are.

Reports that are especially valuable:

- Any input or server behavior that makes the library report
  `VerdictClean` without a definitive `OK` reply from clamd (fail-open).
- Any code path where `err != nil` is returned together with a non-zero
  `ScanResult`.
- Reply-parser confusions (a `FOUND`/`ERROR` reply classified as clean).
- Resource exhaustion beyond the documented bounds (reply-read limits,
  stream size limits, I/O timeouts).

## Threat model

Trust boundaries assumed by the library:

| Component                  | Trust assumption                                        |
| -------------------------- | ------------------------------------------------------- |
| Scanned data (`io.Reader`) | **Untrusted.** Malicious content, unbounded size, failing/slow readers |
| Network path to clamd      | Semi-trusted availability-wise: may fail or stall at any time; replies are bounded and strictly parsed |
| clamd itself               | Trusted for verdicts. If your clamd is compromised, verdicts are meaningless — the library cannot defend against that |
| Configuration (address, limits) | Trusted deployment input. **Never derive the address from request data** |

Design properties relied on:

- **Fail-closed:** every failure path returns the zero `ScanResult`
  (`VerdictUnknown`); unknown replies are `ProtocolError`s, never verdicts.
  `VerdictClean` is produced only by the OK reply forms INSTREAM actually
  emits: a bare `OK`, or `<prefix>: OK` where the prefix contains "stream".
- **Bounded resources:** reply reads are capped (4 KiB line / 1 MiB block),
  each read/write carries a no-progress deadline, streams are size-limited
  client-side (default 25 MiB) *before* bytes are sent, and a partial
  stream is never terminated as if complete. The per-operation deadline
  bounds stalls, not totals: a server dripping one byte per interval can
  stretch a reply read to (reply cap × I/O timeout), so callers must bound
  total scan time with a context deadline, as every example does.
- **No content exposure:** scanned bytes are never logged, stored, or
  embedded in error messages; errors carry classification and metadata only.
- **Protocol hygiene:** clamd is a hard trust dependency, so the protocol
  (unauthenticated cleartext) must run over a unix socket or isolated
  network; this is documented, not enforceable by the library.

Out of scope (not vulnerabilities in this library):

- Malware that ClamAV signatures do not detect, and signature freshness —
  operate freshclam and monitor `Version()` (see docs/operations.md).
- Deployments that expose clamd to untrusted networks or accept files when
  `err != nil`, contrary to the documented contract.
- Vulnerabilities in ClamAV itself — report those to the ClamAV project.

## Supported versions

Security fixes target the latest tagged release. The dependency surface is
the Go standard library only, so keeping current is a `go get -u` away.
