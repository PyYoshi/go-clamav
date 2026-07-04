# Contributing to go-clamav

This is a security-sensitive library. The rules every contributor — human
and AI — works under live in [AGENTS.md](AGENTS.md); read that first. This
file covers the mechanics.

## Setup

- Go 1.26+ (`go.mod` pins the floor; `GOTOOLCHAIN=auto` fetches it).
- Docker with the compose plugin (integration tests).
- `jq` (used by the Claude Code guard hooks; optional otherwise).

Then, once per clone:

```sh
make setup
```

This points `core.hooksPath` at [`githooks/`](githooks/) (commit-msg,
pre-commit and pre-push guards) and checks tooling.

## Everyday commands

| Command | Purpose |
|---|---|
| `make format` | Format with gofumpt + gci |
| `make verify` | Build (incl. integration tags) + lint + tests |
| `make integration` | End-to-end tests against dockerized clamd |
| `make fuzz` | Short fuzz pass over the reply parser |

`make verify` is the Definition-of-Done gate: run it before every push.

## Pull request workflow

Direct pushes to `main` are rejected by repository ruleset; all changes go
through pull requests.

1. Branch from `main` (`feat/...`, `fix/...`, `docs/...`, `chore/...`).
2. Commit with a signed signature, an English commit message (see the
   language policy in AGENTS.md) and **no `Co-Authored-By` trailers**
   (signing is automatic via repo config; the commit-msg hook enforces the
   trailer rule).
3. Push the branch and open a PR (`gh pr create`); fill in the template
   checklist — it mirrors the Definition of Done in AGENTS.md.
4. Wait for the required checks: `unit`, `lint`, `integration (1.4)`,
   `integration (1.5)`.
5. CodeRabbit reviews every PR (in Japanese, with request-changes enabled —
   its CHANGES_REQUESTED state blocks merging):
   - address findings and push fixes;
   - when rejecting a finding, reply on its thread with the reason;
   - once every finding is handled, comment `@coderabbitai resolve` on the
     PR — CodeRabbit re-checks and posts an approving review.
6. Merge with a merge commit: `gh pr merge --merge --delete-branch`
   (squash/rebase merges are disabled so commit signatures survive).

## Design changes

Public API, wire-protocol behavior and security defaults are design-gated:
they need a maintainer-approved ADR in [`docs/adr/`](docs/adr/) before
implementation. Start from [`docs/adr/template.md`](docs/adr/template.md).

## Security issues

Never open a public issue for a vulnerability — follow
[SECURITY.md](SECURITY.md) (GitHub private vulnerability reporting).
