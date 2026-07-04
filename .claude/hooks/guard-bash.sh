#!/usr/bin/env bash
# Claude Code PreToolUse hook for Bash: blocks commands that violate this
# repository's git conventions before they run. Token-based matching keeps
# false positives low (e.g. `git push origin fix/main-detect` and
# `grep Co-Authored-By AGENTS.md` are allowed).
#
# Blocked:
#   - git commit with a Co-Authored-By trailer
#   - git commit/merge/push with --no-verify / --no-gpg-sign (-n on commit)
#   - git push --force / +refspec, and any push targeting main
#   - git config / git -c changing commit.gpgsign or core.hooksPath
#   - gh pr merge --admin (bypasses required checks)
#
# Advisory layer: fail-open without jq; rulesets and CI are authoritative.
set -u

if ! command -v jq >/dev/null 2>&1; then
  echo "guard-bash: jq not found; command guard skipped (install jq, see make setup)." >&2
  exit 0
fi

cmd=$(jq -r '.tool_input.command // empty' 2>/dev/null) || exit 0
[ -n "$cmd" ] || exit 0

block() {
  echo "BLOCKED by repository policy: $1" >&2
  echo "See AGENTS.md (Git rules). If this block is wrong, ask the user before working around it." >&2
  exit 2
}

on_main_branch() {
  [ "$(git symbolic-ref --short -q HEAD 2>/dev/null)" = "main" ]
}

check_git() {
  local tokens=("$@") sub="" i=0 t seg="${*}"

  # Global options: `git -c key=val ...` can change signing/hook behavior
  # for a single invocation, and -C can point at another repository.
  while [ $i -lt ${#tokens[@]} ]; do
    t=${tokens[$i]}
    case "$t" in
    -c | --config-env)
      local kv=${tokens[$((i + 1))]:-}
      case "${kv,,}" in
      commit.gpgsign=false | commit.gpgsign=0 | commit.gpgsign=no | commit.gpgsign=off)
        block "disabling commit signing (git -c commit.gpgsign=...)"
        ;;
      core.hookspath=*)
        block "overriding core.hooksPath bypasses the repository git hooks"
        ;;
      esac
      i=$((i + 2))
      continue
      ;;
    -c*)
      case "${t,,}" in
      -ccommit.gpgsign=false | -ccommit.gpgsign=0 | -ccommit.gpgsign=no | -ccommit.gpgsign=off)
        block "disabling commit signing (git -c commit.gpgsign=...)"
        ;;
      -ccore.hookspath=*)
        block "overriding core.hooksPath bypasses the repository git hooks"
        ;;
      esac
      i=$((i + 1))
      continue
      ;;
    -C | --git-dir | --work-tree | --namespace | --exec-path)
      i=$((i + 2))
      continue
      ;;
    -*)
      i=$((i + 1))
      continue
      ;;
    *)
      sub=$t
      break
      ;;
    esac
  done
  [ -n "$sub" ] || return 0
  local rest=("${tokens[@]:$((i + 1))}")

  case "$sub" in
  commit)
    if grep -qi 'co-authored-by' <<<"$seg"; then
      block "Co-Authored-By trailers are not allowed in commit messages"
    fi
    for t in "${rest[@]}"; do
      case "$t" in
      --no-verify | -n) block "git commit --no-verify skips the repository git hooks" ;;
      --no-gpg-sign) block "all commits must be SSH-signed (no --no-gpg-sign)" ;;
      esac
    done
    ;;
  merge)
    for t in "${rest[@]}"; do
      case "$t" in
      --no-verify) block "git merge --no-verify skips the repository git hooks" ;;
      --no-gpg-sign) block "all commits must be SSH-signed (no --no-gpg-sign)" ;;
      esac
    done
    ;;
  push)
    local nonopt=()
    for t in "${rest[@]}"; do
      case "$t" in
      -f | --force | --force-with-lease | --force-with-lease=* | --force-if-includes)
        block "force-pushing is not allowed"
        ;;
      --no-verify) block "git push --no-verify skips the repository git hooks" ;;
      +*) block "force-push refspecs (+...) are not allowed" ;;
      main | refs/heads/main | *:main | *:refs/heads/main)
        block "pushing to main directly is not allowed; open a pull request"
        ;;
      -*) ;;
      *) nonopt+=("$t") ;;
      esac
    done
    if [ ${#nonopt[@]} -le 1 ] && on_main_branch; then
      block "pushing while on main is not allowed; work on a feature branch"
    fi
    for t in "${nonopt[@]}"; do
      if [ "$t" = "HEAD" ] && on_main_branch; then
        block "pushing main via HEAD is not allowed; open a pull request"
      fi
    done
    ;;
  config)
    if grep -qi 'commit\.gpgsign' <<<"$seg"; then
      case "${seg,,}" in
      *false* | *" 0"* | *" no"* | *" off"*) block "disabling commit signing (commit.gpgsign)" ;;
      esac
    fi
    if grep -qi 'core\.hookspath' <<<"$seg"; then
      block "changing core.hooksPath bypasses the repository git hooks (use make setup)"
    fi
    ;;
  esac
}

check_gh() {
  local seg="${*}"
  if grep -qE '(^|[[:space:]])pr[[:space:]]+merge([[:space:]]|$)' <<<"$seg" &&
    grep -qE '(^|[[:space:]])--admin([[:space:]]|$)' <<<"$seg"; then
    block "gh pr merge --admin bypasses the required status checks"
  fi
}

# Split compound commands on |, ;, & and backticks, then inspect each
# segment that invokes git or gh. Quoted separators over-split, which can
# only cause a rare false block, never a false allow.
while IFS= read -r seg; do
  read -ra tok <<<"$seg" || true
  [ ${#tok[@]} -eq 0 ] && continue
  case "${tok[0]}" in
  git) check_git "${tok[@]:1}" ;;
  gh) check_gh "${tok[@]:1}" ;;
  esac
done < <(printf '%s\n' "$cmd" | tr '|;&`' '\n')

exit 0
