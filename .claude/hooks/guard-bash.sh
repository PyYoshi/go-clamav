#!/usr/bin/env bash
# Claude Code PreToolUse hook for Bash: blocks commands that violate this
# repository's git conventions before they run. Token-based matching keeps
# false positives low (e.g. `git push origin fix/main-detect` and
# `grep Co-Authored-By AGENTS.md` are allowed).
#
# Blocked:
#   - git commit with a Co-Authored-By trailer
#   - git commit/merge/push with --no-verify / --no-gpg-sign (-n on commit)
#   - git push --force / +refspec / --all / --mirror, and any push
#     targeting main
#   - git config / git -c / GIT_CONFIG_* changing commit.gpgsign or
#     core.hooksPath
#   - gh pr merge --admin (bypasses required checks)
#
# git and gh are found behind variable assignments, a path (/usr/bin/git),
# shell keywords and wrappers that run a command (env, sudo, sh -c, xargs,
# ...). Quotes are stripped, short options are read inside clusters (-nm,
# -uf), and long options also by the abbreviations git accepts (--no-verif).
#
# Advisory layer: a string filter cannot see commands assembled at runtime
# (scripts, aliases, variables, exported config), so a deliberate bypass
# remains possible; it also fails open without jq. Rulesets and CI are
# authoritative.
#
# Kept bash 3.2 compatible (macOS /bin/bash): no ${var,,} lowercasing, and
# no `set -u` — empty-array expansion trips it on bash < 4.4.

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

lc() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

# A push later in the same command line runs after any checkout before it,
# so a switch to main earlier in the line counts as being on main.
switched_to_main=0

on_main_branch() {
  [ "$switched_to_main" = 1 ] && return 0
  [ "$(git symbolic-ref --short -q HEAD 2>/dev/null)" = "main" ]
}

# abbrev_of TOKEN OPTION MIN: TOKEN is OPTION or a prefix of it at least MIN
# characters long. git accepts any unambiguous abbreviation of a long
# option, and MIN is set below the point where git starts resolving one.
abbrev_of() {
  [ "${#1}" -ge "$3" ] || return 1
  case "$2" in
  "$1"*) return 0 ;;
  esac
  return 1
}

# short_flag CLUSTER FLAG VALUED: the short-option cluster (-nm) contains
# FLAG before any option in VALUED, which takes the rest of the cluster as
# its value (-mn is -m with the message "n").
short_flag() {
  local s=${1#-} c
  while [ -n "$s" ]; do
    c=${s:0:1}
    [ "$c" = "$2" ] && return 0
    case "$3" in
    *"$c"*) return 1 ;;
    esac
    s=${s:1}
  done
  return 1
}

# check_config_pair OPTION KEY=VALUE: git -c and --config-env set config for
# one invocation. Only an explicit true keeps signing on; a --config-env
# value names an environment variable, so it is never trusted.
check_config_pair() {
  local kv
  kv=$(lc "$2")
  case "$kv" in
  core.hookspath=*)
    block "overriding core.hooksPath bypasses the repository git hooks"
    ;;
  commit.gpgsign=*)
    case "$1:$kv" in
    -c:*=true | -c:*=yes | -c:*=on | -c:*=1) ;;
    *) block "disabling commit signing (git -c commit.gpgsign=...)" ;;
    esac
    ;;
  esac
}

# GIT_CONFIG_PARAMETERS and GIT_CONFIG_COUNT/KEY_n/VALUE_n are the
# environment form of git -c, and reach every git a command runs.
check_config_env() {
  local t
  for t in "$@"; do
    case "$t" in
    GIT_CONFIG_*=*)
      case "$(lc "$t")" in
      *commit.gpgsign*) block "overriding commit signing through GIT_CONFIG_* variables" ;;
      *core.hookspath*) block "overriding core.hooksPath through GIT_CONFIG_* variables bypasses the repository git hooks" ;;
      esac
      ;;
    esac
  done
}

check_git() {
  local tokens=("$@") sub="" i=0 t name seg="${*}"

  # Global options: `git -c key=val ...` can change signing/hook behavior
  # for a single invocation, and -C can point at another repository.
  while [ "$i" -lt "${#tokens[@]}" ]; do
    t=${tokens[$i]}
    case "$t" in
    -c | --config-env)
      check_config_pair "$t" "${tokens[$((i + 1))]}"
      i=$((i + 2))
      continue
      ;;
    --config-env=*)
      check_config_pair --config-env "${t#--config-env=}"
      i=$((i + 1))
      continue
      ;;
    -c*)
      check_config_pair -c "${t#-c}"
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
      --*)
        name=${t%%=*}
        abbrev_of "$name" --no-verify 6 && block "git commit --no-verify skips the repository git hooks"
        abbrev_of "$name" --no-gpg-sign 6 && block "all commits must be SSH-signed (no --no-gpg-sign)"
        ;;
      -*)
        short_flag "$t" n mFCctSu && block "git commit --no-verify skips the repository git hooks"
        ;;
      esac
    done
    ;;
  merge)
    for t in "${rest[@]}"; do
      case "$t" in
      --*)
        name=${t%%=*}
        abbrev_of "$name" --no-verify 6 && block "git merge --no-verify skips the repository git hooks"
        abbrev_of "$name" --no-gpg-sign 6 && block "all commits must be SSH-signed (no --no-gpg-sign)"
        ;;
      esac
    done
    ;;
  push)
    local nonopt=()
    for t in "${rest[@]}"; do
      case "$t" in
      --*)
        name=${t%%=*}
        if abbrev_of "$name" --force 5 || abbrev_of "$name" --force-with-lease 5 ||
          abbrev_of "$name" --force-if-includes 5; then
          block "force-pushing is not allowed"
        fi
        abbrev_of "$name" --no-verify 6 && block "git push --no-verify skips the repository git hooks"
        if abbrev_of "$name" --all 4 || abbrev_of "$name" --mirror 4; then
          block "git push --all/--mirror also pushes main; push a single feature branch"
        fi
        ;;
      -*)
        short_flag "$t" f o && block "force-pushing is not allowed"
        ;;
      +*) block "force-push refspecs (+...) are not allowed" ;;
      main | refs/heads/main | *:main | *:refs/heads/main)
        block "pushing to main directly is not allowed; open a pull request"
        ;;
      *) nonopt+=("$t") ;;
      esac
    done
    if [ "${#nonopt[@]}" -le 1 ] && on_main_branch; then
      block "pushing while on main is not allowed; work on a feature branch"
    fi
    for t in "${nonopt[@]}"; do
      case "$t" in
      HEAD | @)
        on_main_branch && block "pushing main via HEAD is not allowed; open a pull request"
        ;;
      esac
    done
    ;;
  checkout | switch)
    for t in "${rest[@]}"; do
      case "$t" in
      main | -) switched_to_main=1 ;;
      esac
    done
    ;;
  config)
    if grep -qi 'commit\.gpgsign' <<<"$seg"; then
      case "$(lc "$seg")" in
      *false* | *" 0"* | *" no"* | *" off"* | *unset*) block "disabling commit signing (commit.gpgsign)" ;;
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

# find_command WORD...: sets cmd_at to the index of the command word, or -1.
# Variable assignments and shell keywords before it are skipped; behind a
# wrapper that runs a command, the next git or gh word is taken, so wrapper
# options and their values need no parsing.
find_command() {
  local words=("$@") i=0 t
  cmd_at=-1
  while [ "$i" -lt "${#words[@]}" ]; do
    t=${words[$i]}
    case "$t" in
    [A-Za-z_]*=*)
      i=$((i + 1))
      continue
      ;;
    esac
    case "${t##*/}" in
    '!' | '{' | if | then | elif | else | do | while | until) ;;
    env | command | builtin | exec | eval | nohup | nice | time | timeout | sudo | doas | xargs | sh | bash | zsh | dash | ksh)
      i=$((i + 1))
      while [ "$i" -lt "${#words[@]}" ]; do
        case "${words[$i]##*/}" in
        git | gh)
          cmd_at=$i
          return
          ;;
        esac
        i=$((i + 1))
      done
      return
      ;;
    *)
      cmd_at=$i
      return
      ;;
    esac
    i=$((i + 1))
  done
}

# Join backslash-continued lines, split compound commands on |, ;, &,
# backticks and parentheses (the latter catch $(...) command substitutions
# and subshells), strip quotes and backslashes and drop redirections, then
# inspect each segment that invokes git or gh. Splitting and stripping
# ignore quoting, so quoted text that looks like a separator or an option
# can cause a rare false block.
cmd=${cmd//\\$'\n'/ }
while IFS= read -r seg; do
  seg=${seg//\"/}
  seg=${seg//\'/}
  seg=${seg//\\/}
  read -ra tok <<<"$seg"
  words=()
  skip=0
  for t in "${tok[@]}"; do
    if [ "$skip" = 1 ]; then
      skip=0
      continue
    fi
    case "$t" in
    *[\<\>])
      skip=1
      continue
      ;;
    *[\<\>]*) continue ;;
    esac
    words+=("$t")
  done
  [ "${#words[@]}" -eq 0 ] && continue
  check_config_env "${words[@]}"
  find_command "${words[@]}"
  [ "$cmd_at" -ge 0 ] || continue
  case "${words[$cmd_at]##*/}" in
  git) check_git "${words[@]:$((cmd_at + 1))}" ;;
  gh) check_gh "${words[@]:$((cmd_at + 1))}" ;;
  esac
done < <(printf '%s\n' "$cmd" | tr '|;&`()' '\n')

exit 0
