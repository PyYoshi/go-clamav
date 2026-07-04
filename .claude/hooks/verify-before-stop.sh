#!/usr/bin/env bash
# Claude Code Stop hook: one-shot Definition-of-Done check before the agent
# ends its turn.
#
#   1. If Go sources (*.go, go.mod) differ from the state recorded by the
#      last successful `make verify` (scripts/record-verified.sh), block once
#      with a reminder to run it. Content-hash based, so commits, stashes and
#      checkouts that leave bytes identical never re-trigger.
#   2. If exactly one of README.md / README.ja.md changed, remind once that
#      the two must stay in sync.
#
# stop_hook_active is set when a previous Stop block already continued the
# turn — in that case allow stopping, so the agent is nudged exactly once.
set -u

root=${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}
cd "$root" || exit 0

command -v jq >/dev/null 2>&1 || exit 0

if [ "$(jq -r '.stop_hook_active // false' 2>/dev/null)" = "true" ]; then
  exit 0
fi

reasons=()

# --- 1. Unverified Go changes -------------------------------------------
go_changed=false
if [ -n "$(git status --porcelain -- '*.go' go.mod 2>/dev/null)" ]; then
  go_changed=true
elif git rev-parse -q --verify origin/main >/dev/null 2>&1 &&
  [ -n "$(git diff --name-only origin/main...HEAD -- '*.go' go.mod 2>/dev/null)" ]; then
  go_changed=true
fi

if [ "$go_changed" = "true" ]; then
  current=$(./scripts/go-state-hash.sh 2>/dev/null || echo unknown)
  recorded=$(cat "$(git rev-parse --git-dir)/harness/verified" 2>/dev/null || echo none)
  if [ "$current" != "$recorded" ]; then
    reasons+=("Go sources changed but 'make verify' has not passed against the current state. Run 'make format && make verify' (and 'make integration' if client/conn/commands/proto/docker changed), fix anything it reports, then finish.")
  fi
fi

# --- 2. README pair drift -------------------------------------------------
readme_changed=$(
  {
    git diff --name-only HEAD -- README.md README.ja.md 2>/dev/null
    git rev-parse -q --verify origin/main >/dev/null 2>&1 &&
      git diff --name-only origin/main...HEAD -- README.md README.ja.md 2>/dev/null
  } | sort -u
)
if [ "$readme_changed" = "README.md" ] || [ "$readme_changed" = "README.ja.md" ]; then
  reasons+=("Only ${readme_changed} changed. README.md and README.ja.md must stay in sync — update the counterpart, or state explicitly why the change does not apply to it.")
fi

if [ ${#reasons[@]} -gt 0 ]; then
  printf '%s\n' "${reasons[@]}" >&2
  exit 2
fi

exit 0
