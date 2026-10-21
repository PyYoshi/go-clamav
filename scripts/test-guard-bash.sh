#!/usr/bin/env bash
# Regression table for the Claude Code git-command guard
# (.claude/hooks/guard-bash.sh). Every row of
# scripts/testdata/guard-bash-cases.tsv is fed to the hook as the JSON a
# Claude Code PreToolUse event carries, from a scratch repository on the
# row's branch, and must be blocked (exit 2) or allowed (exit 0) as the row
# says.
#
# The hook is inert without jq, so a local run without jq is skipped with a
# warning; in CI (CI set) a missing jq fails the run.
#
# Usage: test-guard-bash.sh [HOOK]   (default: .claude/hooks/guard-bash.sh)
# Exit codes: 0 = every row as expected, 1 = a mismatch, 2 = setup error.
set -u

top=$(cd "$(dirname "$0")/.." && pwd)
hook=${1:-$top/.claude/hooks/guard-bash.sh}
cases=$top/scripts/testdata/guard-bash-cases.tsv

if ! command -v jq >/dev/null 2>&1; then
  if [ -n "${CI:-}" ]; then
    echo "test-guard-bash: jq not found; the guard hook cannot be tested." >&2
    exit 2
  fi
  echo "test-guard-bash: jq not found; guard hook table skipped (CI runs it)." >&2
  exit 0
fi

# Inside a git hook these would point the hook's branch lookup at this
# repository instead of the scratch ones.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE

scratch=$(mktemp -d) || exit 2
trap 'rm -rf "$scratch"' EXIT
for b in main feature; do
  git init -q "$scratch/$b" &&
    git -C "$scratch/$b" symbolic-ref HEAD "refs/heads/$b" || exit 2
done

pass=0
fail=0
while IFS=$'\t' read -r expect branch command || [ -n "${expect:-}" ]; do
  case "$expect" in
  '' | '#'*) continue ;;
  block | allow) ;;
  *)
    echo "test-guard-bash: bad row: $expect" >&2
    exit 2
    ;;
  esac
  case "$branch" in
  main | feature) ;;
  *)
    echo "test-guard-bash: bad branch in row: $branch" >&2
    exit 2
    ;;
  esac
  command=${command//<NL>/$'\n'}
  rc=0
  (cd "$scratch/$branch" &&
    jq -n --arg c "$command" '{tool_input: {command: $c}}' | bash "$hook" >/dev/null 2>&1) || rc=$?
  case "$rc" in
  0) got=allow ;;
  2) got=block ;;
  *) got="exit $rc" ;;
  esac
  if [ "$got" = "$expect" ]; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
    printf 'test-guard-bash: expected %s, got %s (on %s): %q\n' "$expect" "$got" "$branch" "$command" >&2
  fi
done <"$cases"

if [ "$pass" -eq 0 ] && [ "$fail" -eq 0 ]; then
  echo "test-guard-bash: no rows read from $cases" >&2
  exit 2
fi
echo "test-guard-bash: $pass passed, $fail failed"
[ "$fail" -eq 0 ] || exit 1
