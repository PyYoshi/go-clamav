---
name: release
description: Cut a go-clamav release — move [Unreleased] CHANGELOG entries to a version section via PR, then create a signed v* tag and the GitHub release.
disable-model-invocation: true
---

# Release procedure

Release tags (`v*`) are protected: they must be signed and can never be
deleted or moved. Do not proceed if any step fails — ask the user.

## 1. Preconditions

- `git checkout main && git pull` — working tree clean, local main equals
  `origin/main`.
- CI on main is green (`gh run list --workflow CI --branch main -L 1`).
- `[Unreleased]` in CHANGELOG.md actually contains entries.

## 2. Choose the version

Semantic Versioning against the `[Unreleased]` content: breaking public
API → major (pre-1.0: minor), features → minor, fixes only → patch.
Confirm the version with the user before continuing.

## 3. CHANGELOG PR

`main` is protected, so the CHANGELOG cut itself goes through a PR
(use the pr-flow skill):

- Move `[Unreleased]` entries under a new `## [X.Y.Z] - YYYY-MM-DD`.
- Keep an empty `[Unreleased]` section on top.
- Update the compare links at the bottom (`[Unreleased]`, `[X.Y.Z]`).

## 4. Tag and release

After that PR is merged:

```sh
git checkout main && git pull
git tag -s vX.Y.Z -m "go-clamav vX.Y.Z"
git tag -v vX.Y.Z        # or: git log -1 --format='%G?' vX.Y.Z
git push origin vX.Y.Z
gh release create vX.Y.Z --title "vX.Y.Z" --notes "<the new CHANGELOG section>"
```

The tag must be annotated and signed (`-s`); an unsigned tag is rejected by
the tag ruleset. If 1Password prompts for the signature, let the user
approve it.
