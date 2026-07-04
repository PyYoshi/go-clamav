# ADR-0002: Fail-closed error model

- Status: Accepted
- Date: 2026-07-04

## Context

The library exists to decide whether an untrusted upload may be accepted.
Every failure mode — clamd down, timeout, oversized input, unparseable
reply — needs a defined answer to "may the file pass?". Most existing Go
clamd clients return `(result, err)` pairs where a partially populated
result can be misread as a verdict even when `err != nil`, which is a
fail-open trap for callers.

## Decision

Every error path is fail-closed, mechanically:

1. If `err != nil`, the returned `ScanResult` is always the **zero value**,
   whose `Verdict` is `VerdictUnknown`; a zero `ScanResult` never reports
   `Clean() == true`.
2. Replies are classified with priority **FOUND > ERROR > OK**; a reply
   that cannot be positively classified becomes a `ProtocolError`
   (`OutcomeUnknown`), never a clean verdict.
3. Errors form a small taxonomy — `ClamdError`, `ProtocolError`,
   `ConnectionError`, the `ErrSizeLimitExceeded` sentinel — and
   `IsRetryable()` tells callers which failures are worth retrying.
   Rejection remains the caller's only safe response to any error.

## Rationale

- A zero-value result on error removes the fail-open trap by construction:
  there is no code path in which an error coexists with an accept-shaped
  result.
- Suffix-driven classification with FOUND first means an infected verdict
  can never be downgraded by an unexpected prefix, and novel/garbled
  replies degrade to "unknown", the safe direction.
- The taxonomy keeps operational reactions (retry, alert, reject) apart
  from the security decision, which is always "not clean unless OK".

## Considered objections

- *Callers may want partial information on error* (e.g. the raw reply).
  Exposed via error values and wrapping, never via `ScanResult`.
- *Treating size-limit hits as errors rejects large clean files.* This is
  policy: the limit exists so clamd's own `StreamMaxLength` (which clamd
  may answer with a misleadingly clean-looking reply) is never reached;
  callers opt out explicitly with `NoSizeLimit`.

## Consequences

- Callers can apply the contract with one rule: accept only when
  `err == nil && result.Clean()`.
- Tests must assert the zero result on every error path; the review
  contract (.coderabbit.yaml, AGENTS.md) treats any deviation as a
  critical defect.
