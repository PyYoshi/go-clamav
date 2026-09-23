---
name: pr-flow
description: Land current changes on main via the required PR workflow of this repository — feature branch, signed commits, required checks, independent review, merge-commit merge. Use when asked to open a PR, ship/land changes, or merge work into main.
---

# PR flow for PyYoshi/go-clamav

`main` only accepts signed merge commits from PRs with green required
checks, and every PR gets an independent review before it is merged. Follow
the steps in order; never bypass a step with `--no-verify`, force pushes or
`gh pr merge --admin`.

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

## 5. Independent review

No bot review gates the merge, so this step is where the PR gets reviewed.
Have the diff reviewed against the Review checklist in AGENTS.md by a
reviewer that is not the session that wrote it: the maintainer, or a
separate review run such as a fresh reviewer agent or Codex
`adversarial-review` (pass the checklist as its focus text).

- Address valid findings and push the fixes; the required checks rerun,
  and the fixes go back to the reviewer — the review must cover the commit
  that is merged.
- For findings you reject, reply in the PR with the concrete reason (never
  drop one silently).
- Record the reviewed commit SHA in the PR. Merge only once every finding,
  whatever its severity, is fixed or answered, then tick the review item
  in the PR checklist.

## 6. Merge and clean up

```sh
gh pr merge <num> --merge --delete-branch   # merge commit only
git checkout main && git pull
```

Squash/rebase are disabled repository-wide. After the merge, confirm the
merge commit shows `verified` on GitHub (`gh api repos/{owner}/{repo}/commits/main --jq .commit.verification.verified`).
