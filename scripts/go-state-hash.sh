#!/usr/bin/env bash
# Prints a single digest over the current Go source state: the contents of
# all tracked and untracked *.go files plus go.mod, in a deterministic order.
#
# `make verify` records this digest (scripts/record-verified.sh); the Claude
# Code stop hook (.claude/hooks/verify-before-stop.sh) recomputes it to
# decide whether verification is still current. Content-based on purpose:
# checkout/stash/format round-trips that leave bytes identical do not
# invalidate a recorded verification. pipefail so a failing stage can never
# produce a wrong-but-plausible digest.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

digest() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum
  else
    shasum -a 256
  fi
}

{
  git ls-files -- '*.go' go.mod
  git ls-files --others --exclude-standard -- '*.go'
} | sort -u | while IFS= read -r f; do
  [ -f "$f" ] || continue # skip files deleted from the worktree
  printf '%s ' "$f"
  digest <"$f"
done | digest | awk '{print $1}'
