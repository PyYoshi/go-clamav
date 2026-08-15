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

Upstream verification settles what the protocol actually requires. In
`clamd/scanner.c` (checked on `rel/1.4` and `rel/1.5`), `scanfd()` sets
`reply_fdstr = "stream"` unconditionally on the INSTREAM path, and the
clean reply is `conn_reply_single(conn, reply_fdstr, "OK")` — so INSTREAM
always answers `stream: OK`. The `instream(local)` and
`instream(<ip>@<port>)` strings built a few lines earlier go only to
logging, `virusaction()` and the thread-manager task name; they never
reach a reply. Note also the upstream spelling has no space, while this
repository's parser, tests and docs carried `instream (local)` — a form
that has never existed on the wire or in clamd's source.

## Decision

`OutcomeClean` is produced only by an exact, case-sensitive allowlist of
reply lines (after the existing trailing `" \t\r\n\x00"` trim):
`stream: OK`, which is what clamd's INSTREAM path replies, plus a bare
`OK` kept for compatibility. FOUND and ERROR classification stays
suffix-driven. Every other reply remains `OutcomeUnknown`, which the
client surfaces as a `ProtocolError` (fail-closed).

## Rationale

- clamd's INSTREAM path emits exactly one clean form, `stream: OK`;
  matching it exactly is the narrowest predicate that keeps working
  deployments working. This argument was decisive, and it is also why the
  previously accepted `instream (local): OK` is dropped rather than kept:
  no clamd emits it, so no deployment depends on it, and an unnecessary
  entry on a clean-verdict allowlist points the wrong way in a
  fail-closed control.
- The bare `OK` entry is not a clamd INSTREAM reply either — it is a
  compatibility entry, not part of the protocol form above. It is kept
  because it predates this ADR, is already an exact match with no attack
  surface, and removing documented behavior needs a stronger reason than
  symmetry.
- The change can only move replies from "clean" to "protocol error" — a
  strictly fail-closed direction. The residual risk is availability, not
  a wrong verdict, and the required integration matrix (clamd 1.4/1.5
  over unix and TCP) plus the weekly `latest` canary surface real-world
  drift before it reaches users.
- This refines the "prefix-agnostic parser" mitigation recorded in
  ADR-0001 for the OK form only. ADR-0001 stays a historical record: its
  original text is left intact and annotated with a dated correction
  pointing here, rather than rewritten to match what we now know.

## Considered objections

- Dropping `instream (local): OK` removes an accepted form. Accepted: it
  was never a real clamd reply (see Context), so the only way to observe
  the change is to have been sending a hand-crafted reply, and that now
  fails closed with a visible `ProtocolError` rather than a clean
  verdict.
- Keeping the upstream spelling `instream(local): OK` as a defensive
  entry was considered and rejected: `fdstr` reaches no reply on the
  INSTREAM path in any released version, so it would allowlist a second
  string clamd cannot send.
- Dropping the bare `OK` entry too was considered (clamd 1.x always
  prefixes INSTREAM replies). Rejected: it is already an exact match with
  no attack surface.

## Consequences

- Reply-format drift in future clamd versions surfaces as `ProtocolError`
  instead of being silently accepted; the CI matrix and canary act as the
  early-warning system, and accepting a new form requires an ADR-gated
  change here.
- The fuzz invariant in `internal/proto/fuzz_test.go` pins the exact
  allowlist, so any future loosening fails the fuzz suite.
- SECURITY.md and docs/operations.md now document the allowlist instead
  of the substring rule.
