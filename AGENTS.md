# AGENTS.md — rules for AI and human contributors

go-clamav is a **fail-closed security control**: a zero-dependency Go client
for clamd used to scan untrusted user uploads. Bugs here do not crash
applications — they let malware through. Read this file before changing
anything.

Design decisions are made by humans; implementation may be done by AI
agents. This file is the contract both work under. Claude Code loads it via
CLAUDE.md; other agents (e.g. Codex) read it directly.

## Non-negotiable invariants

Changing any of these is a defect, not a refactor:

1. **Errors never carry verdicts.** When a call returns `err != nil`, the
   `ScanResult` must be the zero value (`Verdict == VerdictUnknown`). A zero
   `ScanResult` never reports `Clean() == true`.
2. **Unknown never means clean.** A clamd reply that cannot be positively
   classified is a `ProtocolError`, never a clean verdict. The parser in
   `internal/proto` classifies with priority FOUND > ERROR > OK and maps
   unknown replies to `OutcomeUnknown`. Never relax this toward fail-open.
3. **Limits are load-bearing.** Reply-read bounds, I/O deadlines and the
   client-side size limit bound resource use against a hostile peer. Do not
   raise, remove or bypass them without an approved ADR.
4. **Partial streams must never look complete.** The INSTREAM zero-length
   terminator is sent only after a fully successful stream; short writes
   must surface as errors.
5. **Zero dependencies.** Standard library only. `go.mod` must never gain a
   `require` directive (CI fails if it does; see ADR-0003).
6. **EICAR is never assembled in this repository.** The 68-byte test string
   exists only split into parts (`internal/clamdtest/eicar.go`) or
   hex-encoded (`docker/clamd/db/eicar.ndb`), so checkouts are never
   quarantined by resident antivirus. Use `clamdtest.EICAR()` in tests.
7. **Scanned content stays out of logs and error messages.** Errors may
   describe the failure, never the bytes being scanned. The clamd address
   is configuration fixed at `New` time — never derive it from request or
   scanned data.

These invariants are enforced in layers: tests, CI, git hooks, Claude Code
hooks, CodeRabbit path instructions and GitHub rulesets. **Weakening a
guard layer (disabling a hook, deleting a check, softening an instruction)
is itself a critical defect.**

## Definition of Done

A change is done only when all of the following hold:

- `make verify` passes (build incl. integration tags + lint + tests) — it
  also records the verified source state, which the Claude Code stop hook
  checks.
- `make integration` passes whenever `client.go`, `conn.go`,
  `commands.go`, `internal/proto/` or `docker/` changed.
- `README.md` and `README.ja.md` are updated **together** (they are
  mirrors of each other).
- `CHANGELOG.md` has an entry under `[Unreleased]` for any user-visible
  change (Keep a Changelog format).
- godoc and code comments are written in English.

## Design gate

Humans decide design; agents implement it. **Stop and ask the maintainer
(or reference an accepted ADR in `docs/adr/`) before:**

- adding, changing or removing any exported identifier (public API);
- changing wire-protocol behavior (`internal/proto`, INSTREAM framing,
  reply classification);
- changing security defaults (size limit, timeouts, reply bounds,
  fail-closed error mapping);
- introducing a dependency, a new tool, or a new CI job.

Accepted designs are recorded as `docs/adr/NNNN-title.md`
(start from `docs/adr/template.md`).

## Git rules

- **Never** add `Co-Authored-By` or other attribution trailers to commits.
- Every commit must be signed. Signing is automatic via repo config;
  verify with `git log --format='%h %G?'` (expect `G`).
- Never push to `main`. Work on a feature branch, open a PR, wait for the
  four required checks (`unit`, `lint`, `integration (1.4)`,
  `integration (1.5)`) and CodeRabbit, then merge with a merge commit
  (`gh pr merge --merge --delete-branch`). Squash and rebase merges are
  disabled to preserve signatures.
- Never use `--no-verify`, `--no-gpg-sign`, force pushes,
  `gh pr merge --admin`, or `core.hooksPath` overrides.
- Run `make setup` once per clone to enable the repository git hooks.

See CONTRIBUTING.md for the full pull-request and CodeRabbit workflow.

## Commands

| Command | Purpose |
|---|---|
| `make setup` | One-time: enable git hooks, check tooling |
| `make verify` | Build + lint + test; records the verified state |
| `make format` | gofumpt + gci via golangci-lint fmt |
| `make test` | go vet + race-enabled unit tests |
| `make integration` | End-to-end tests against dockerized clamd |
| `make fuzz` | Short fuzz pass over the reply parser |

## Harness layout

- `scripts/` — shared guard logic (EICAR scan, verified-state recording)
- `githooks/` — commit-msg / pre-commit / pre-push (enabled by `make setup`)
- `.claude/` — Claude Code hooks (EICAR guard, git-command guard, stop-time
  DoD check) and skills (`pr-flow`, `release`)
- `docs/adr/` — architecture decision records (the design gate's artifact)
