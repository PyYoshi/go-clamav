---
name: pr-flow
description: Land current changes on main via the required PR workflow of this repository — feature branch, signed commits, required checks, CodeRabbit review handling, merge-commit merge. Use when asked to open a PR, ship/land changes, or merge work into main.
---

# PR flow for PyYoshi/go-clamav

`main` only accepts merge commits from PRs with green required checks and a
non-blocking CodeRabbit review. Follow the steps in order; never bypass a
step with `--no-verify`, force pushes or `gh pr merge --admin`.

## 1. Before committing

- The Definition of Done in AGENTS.md holds — in particular `make verify`
  passes and README.md/README.ja.md/CHANGELOG.md are consistent.
- Work is on a feature branch (`feat/...`, `fix/...`, `docs/...`,
  `chore/...`). If still on `main`, create one now.

## 2. Commit and push

- Commit normally; signing is automatic (1Password may prompt the user —
  if signing fails, tell the user instead of retrying with signing off).
- No `Co-Authored-By` trailers (commit-msg hook rejects them).
- Confirm signatures: `git log --format='%h %G?' origin/main..HEAD` — every
  line must end with `G`.
- `git push -u origin <branch>`.

## 3. Open the PR

```sh
gh pr create --title "<imperative summary>" --body "<template-based body>"
```

Fill the checklist from `.github/PULL_REQUEST_TEMPLATE.md` truthfully —
tick only what was actually done.

## 4. Wait for required checks

```sh
gh pr checks --watch
```

Required: `unit`, `lint`, `integration (1.4)`, `integration (1.5)`. Fix
failures and push; never merge around them.

## 5. Handle CodeRabbit

CodeRabbit reviews in Japanese with request-changes enabled; its
CHANGES_REQUESTED review blocks the merge (mergeStateStatus=BLOCKED).

- Address valid findings, push the fixes.
- For findings you reject, reply on the finding's thread with the concrete
  reason (never resolve silently).
- When every finding is handled, comment on the PR:
  `@coderabbitai resolve` — CodeRabbit re-checks and posts an approving
  review; the merge state becomes CLEAN.

## 6. Merge and clean up

```sh
gh pr merge <num> --merge --delete-branch   # merge commit only
git checkout main && git pull
```

Squash/rebase are disabled repository-wide. After the merge, confirm the
merge commit shows `verified` on GitHub (`gh api repos/{owner}/{repo}/commits/main --jq .commit.verification.verified`).
