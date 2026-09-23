# ADR-0007: Require a NUL-terminated reply for clean verdicts

- Status: Accepted
- Date: 2026-09-23

## Context

Every command is sent in z form, and the clamd protocol specifies that
replies use the terminator the command requested. From the clamd(8) man
page (`docs/man/clamd.8.in`, identical on `rel/1.4` and `rel/1.5`):

> It's recommended to prefix clamd commands with the letter **z** (eg.
> zSCAN) to indicate that the command will be delimited by a NULL
> character and that clamd should continue reading command data until a
> NULL character is read. [...] Clamd replies will honour the requested
> terminator in turn.

A complete reply to a z-form command therefore ends with a NUL. The
implementation matches the documentation: `get_cmd()` in
`clamd/server-th.c` sets the reply terminator to `'\0'` for a `z` prefix,
and every reply helper in `clamd/session.c` (`conn_reply_single`,
`conn_reply`, `conn_reply_virus`, `conn_reply_error`, ...) appends
`conn->term`.

`proto.ReadLine` nevertheless accepted data followed by EOF — a reply the
protocol does not define as complete — as a complete reply, to tolerate a
server that closes right after replying. For the
INSTREAM verdict that tolerance points the wrong way: a connection cut
mid-reply leaves a prefix of the real reply, and a prefix can be an
allowlisted clean line (ADR-0005). A detection for a signature whose name
starts with `OK` — `stream: OK.Custom-1 FOUND` — cut after `stream: OK`
(or `stream: OK `; trailing blanks are trimmed) read as clean. A 2026-09
quality and security review (finding 3) raised this.

The likelihood is low: it needs such a signature name and a cut at exactly
that byte. An on-path attacker could forge a whole reply anyway, which the
threat model already puts out of scope (SECURITY.md). This is hardening,
not a fix for a practical fail-open.

## Decision

A clean verdict is produced only from a reply that ended at its NUL
terminator. `proto.ReadLine` reports whether it saw the terminator; an
INSTREAM reply that would classify as clean but ended at EOF fails as a
`*ProtocolError`. Unterminated FOUND and ERROR replies are classified as
before, and admin replies (PING, VERSION, RELOAD) keep the EOF tolerance.

## Rationale

- Truncation can only shorten a reply, and the clean outcome is the only
  one where a shortened reply is dangerous. Requiring completeness exactly
  there closes the gap without touching any other path. This argument was
  decisive.
- It follows the documented protocol, at no compatibility cost for real
  clamd: the man page specifies the NUL and the implementation always
  sends it (see Context), and the integration matrix (clamd 1.4/1.5 over
  unix and TCP) exercises the clean path against real servers.
- `ProtocolError`, not `ConnectionError`: clamd emits each reply and its
  NUL in a single `mdprintf` call, so an OK without the NUL most plausibly
  comes from a non-conforming peer (a proxy behind `WithDialFunc`, an
  emulator) that will fail the same way every time — exactly the format
  drift ADR-0005 routes to `ProtocolError`. It also gives one rule for
  cut-short replies: the same reply cut a few bytes later
  (`stream: OK.Custom-1 FOU`) is already unknown, hence a `ProtocolError`.
- The mid-stream recovery path (`recoverStreamError`) needs no change: an
  OK received there is already rejected as a `ProtocolError`.

## Considered objections

- Require the terminator for every INSTREAM reply, FOUND and ERROR
  included. Rejected: a truncated FOUND or ERROR can only reject, and
  turning a truncated FOUND into a transport error would discard a real
  detection signal (quarantine flows) for no safety gain.
- Make `ReadLine` strict for all callers (EOF without NUL is an error).
  Rejected for the same reason, and it would change admin command
  behavior, which carries no verdict, with no security benefit.
- Leave it, since the scenario is improbable. Rejected: the check costs a
  boolean, and it makes the code keep SECURITY.md's promise that
  `VerdictClean` comes only from a definitive OK reply.
- Report it as a retryable read `ConnectionError` (`io.ErrUnexpectedEOF`),
  like a close with no reply at all. Rejected in review: a connection
  dying inside clamd's single reply write is far less likely than a
  non-conforming peer, so retries would re-stream the payload (up to the
  size limit) against a failure that does not go away, and operators
  would see transport errors instead of the `ProtocolError` that marks
  format drift. It would also make `io.ErrUnexpectedEOF` match both a
  truncated upload (the uploader's fault) and a server-side problem.

## Consequences

- A non-conforming server or proxy that sends `stream: OK` without the NUL
  now produces non-retryable `ProtocolError`s instead of clean verdicts —
  visible and fail-closed, and documented as a symptom in
  docs/operations.md.
- `proto.ReadLine` returns a third value, `terminated`. `FuzzReadLine`
  pins that it is reported exactly when the input contained a NUL.
- SECURITY.md states the rule next to the ADR-0005 allowlist.
