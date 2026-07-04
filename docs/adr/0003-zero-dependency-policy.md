# ADR-0003: Zero-dependency policy

- Status: Accepted
- Date: 2026-07-04

## Context

The library sits in the security decision path of applications that accept
untrusted uploads. Every third-party module in that path becomes part of
the users' supply chain: its CVEs, its maintainers, its transitive tree.
The problem domain — a line-oriented socket protocol with length-prefixed
framing — is small and fully covered by the Go standard library.

## Decision

The public module depends on the **standard library only**. `go.mod` must
not gain a `require` directive. Development tooling (golangci-lint,
govulncheck) is invoked via `go run` pins in the Makefile and never becomes
a module dependency.

## Rationale

- **Supply-chain surface.** A security control that itself imports
  third-party code weakens the very guarantee it provides; stdlib-only
  keeps the auditable surface to this repository plus the Go project.
- **Auditability.** The entire scan path can be read in one sitting;
  vendoring debates, lockfile drift and dependabot noise for runtime deps
  disappear.
- **Portability.** Combined with ADR-0001 (no cgo), consumers build with
  `CGO_ENABLED=0` and cross-compile trivially.

## Considered objections

- *Test helpers would be easier with assert/require libraries.* Table
  tests and `t.Fatalf` are sufficient; the test tree follows the same
  policy so `go.mod` stays empty.
- *A future feature might genuinely need a dependency.* Then the policy is
  revisited via a superseding ADR — the design gate in AGENTS.md — not by
  a PR that happens to add one.

## Consequences

- CI fails if `go.mod` contains `require` (enforced in the `lint` job).
- Small utilities are reimplemented rather than imported; reviewers treat
  any new import outside the stdlib as a critical finding.
