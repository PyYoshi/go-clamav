#!/usr/bin/env bash
# Scans for the assembled 68-byte EICAR test string.
#
# Repository policy: the EICAR string may exist only split into parts
# (internal/clamdtest/eicar.go) or hex-encoded (docker/clamd/db/eicar.ndb),
# so that a checkout of this repository is never quarantined by a resident
# antivirus scanner. This script assembles the pattern from hex at runtime,
# keeps it in memory only, and never prints matching content — only names.
#
# Usage:
#   check-eicar.sh staged    # scan the git index (pre-commit)
#   check-eicar.sh tracked   # scan tracked files in the worktree (CI)
#   check-eicar.sh stdin     # scan standard input (pre-push diffs, hooks)
#
# Exit codes: 0 = clean, 1 = EICAR found, 2 = usage or scan error.
# A scan error never passes as clean (fail-closed).
set -u

EICAR_HEX="58354f2150254041505b345c505a58353428505e2937434329377d2445494341522d5354414e444152442d414e544956495255532d544553542d46494c452124482b482a"

pattern=""
i=0
while [ "$i" -lt "${#EICAR_HEX}" ]; do
  pattern+=$(printf "\\x${EICAR_HEX:$i:2}")
  i=$((i + 2))
done

fail() {
  echo "check-eicar: assembled EICAR test string detected ($1)." >&2
  echo "check-eicar: keep it split or hex-encoded; see internal/clamdtest/eicar.go." >&2
  exit 1
}

hits=""
where=""
case "${1:-}" in
stdin)
  grep -qF -- "$pattern"
  rc=$?
  where="in input"
  ;;
staged)
  hits=$(git grep -lF --cached -e "$pattern" -- .)
  rc=$?
  where="staged: ${hits//$'\n'/, }"
  ;;
tracked)
  hits=$(git grep -lF -e "$pattern" -- .)
  rc=$?
  where="tracked: ${hits//$'\n'/, }"
  ;;
*)
  echo "usage: $0 staged|tracked|stdin" >&2
  exit 2
  ;;
esac

# grep/git grep: 0 = match, 1 = no match, anything else = the scan itself
# failed. Only a clean "no match" may pass.
case "$rc" in
0) fail "$where" ;;
1) exit 0 ;;
*)
  echo "check-eicar: scan failed (exit $rc); failing closed." >&2
  exit 2
  ;;
esac
