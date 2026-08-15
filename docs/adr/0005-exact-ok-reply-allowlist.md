# ADR-0005: Accept clean verdicts only from an exact OK reply allowlist

- Status: Accepted
- Date: 2026-08-15

## Context

`ParseScanResponse` classified a `<prefix>: OK` reply as clean whenever the
prefix contained the substring "stream", case-insensitively. A 2026-08
security audit (finding F-2) showed this also accepts forms clamd never
emits — `foostream: OK`, `STREAM: OK`, `not a stream: OK`. clamd is a
trusted verdict source in the threat model (SECURITY.md), so the leniency
adds no practical attack surface today, but it is wider than the protocol
requires: a middlebox or an unrelated upstream change could coin an
accepted form by accident.

The clamd 1.4 source (`clamd/scanner.c`) shows the INSTREAM reply prefix
is the constant `"stream"` (`reply_fdstr`); the `instream (local)` /
`instream (<ip>@<port>)` strings are built for internal logging only and
never appear in wire replies, for every clamd line in support (1.4 LTS,
1.5, and the canary-tracked `latest`).

## Decision

`OutcomeClean` is produced only by an exact, case-sensitive allowlist of
reply lines (after the existing trailing `" \t\r\n\x00"` trim): `OK`,
`stream: OK`, and `instream (local): OK`. FOUND and ERROR classification
stays suffix-driven. Every other reply remains `OutcomeUnknown`, which the
client surfaces as a `ProtocolError` (fail-closed).

## Rationale

- The supported protocol needs exactly one form (`stream: OK`); matching
  it exactly is the narrowest predicate that keeps working deployments
  working. This argument was decisive.
- The change can only move replies from "clean" to "protocol error" — a
  strictly fail-closed direction. The residual risk is availability, not
  a wrong verdict, and the required integration matrix (clamd 1.4/1.5
  over unix and TCP) plus the weekly `latest` canary surface real-world
  drift before it reaches users.
- `instream (local): OK` stays as a legacy-compat entry: it was the
  documented accepted form and keeping it costs nothing.
- This refines the "prefix-agnostic parser" mitigation recorded in
  ADR-0001 for the OK form only; ADR-0001 itself is a historical record
  and is not edited.

## Considered objections

- Ancient, long-EOL clamd builds derived the reply prefix from `fdstr`,
  which over IPv4 TCP would have produced `instream (<ip>@<port>): OK`;
  the allowlist rejects that form. Accepted: those versions are years
  past EOL and the failure mode is a visible `ProtocolError`, never a
  wrong verdict.
- Dropping the bare `OK` entry too was considered (clamd 1.x always
  prefixes INSTREAM replies). Rejected: it is already an exact match with
  no attack surface, and removing documented behavior needs a stronger
  reason than symmetry.

## Consequences

- Reply-format drift in future clamd versions surfaces as `ProtocolError`
  instead of being silently accepted; the CI matrix and canary act as the
  early-warning system, and accepting a new form requires an ADR-gated
  change here.
- The fuzz invariant in `internal/proto/fuzz_test.go` pins the exact
  allowlist, so any future loosening fails the fuzz suite.
- SECURITY.md and docs/operations.md now document the allowlist instead
  of the substring rule.
