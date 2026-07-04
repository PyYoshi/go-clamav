#!/usr/bin/env bash
# Claude Code PreToolUse hook for Edit|Write: blocks any file change that
# would introduce the assembled EICAR test string.
#
# The tool input arrives as JSON on stdin, where the EICAR string would be
# escaped (it contains a backslash) — so a raw match on stdin would never
# fire. jq decodes every string value first; the decoded stream is matched
# by scripts/check-eicar.sh, which assembles the pattern from hex in memory.
#
# This is an advisory layer: if jq is unavailable it warns and allows
# (fail-open); the git hooks and CI scan are the enforcing layers.
set -u

root=${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}

if ! command -v jq >/dev/null 2>&1; then
  echo "guard-eicar: jq not found; EICAR guard skipped (install jq, see make setup)." >&2
  exit 0
fi

if ! jq -r '.tool_input | .. | strings' 2>/dev/null | "$root/scripts/check-eicar.sh" stdin; then
  echo "BLOCKED: this change would introduce the assembled 68-byte EICAR test string." >&2
  echo "Repository policy: keep it split or hex-encoded so checkouts are never quarantined by resident AV. Use internal/clamdtest.EICAR() in tests; see AGENTS.md." >&2
  exit 2
fi

exit 0
