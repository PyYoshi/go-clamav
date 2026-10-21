#!/usr/bin/env bash
# Claude Code PreToolUse hook for Bash: blocks commands that violate this
# repository's git conventions before they run. Token-based matching keeps
# false positives low (e.g. `git push origin fix/main-detect` and
# `grep Co-Authored-By AGENTS.md` are allowed).
#
# Blocked:
#   - git commit when the command line carries a Co-Authored-By trailer
#   - --no-verify / --no-gpg-sign on any git command (-n on commit)
#   - git push --force / +refspec / --all / --branches / --mirror, matching
#     (:) and brace-expanded refspecs, wildcard refspecs that match main,
#     and any push targeting main; git send-pack (skips the pre-push hook)
#   - git config / git -c / GIT_CONFIG_* changing commit.gpgsign or
#     core.hooksPath, or defining aliases, mirror remotes, push refspecs or
#     a push.default that can push main (matching, upstream); git remote
#     --mirror
#   - gh pr merge --admin (bypasses required checks), and gh aliases
#     carrying --admin
#
# git and gh are found behind variable assignments, a path (/usr/bin/git),
# shell keywords and wrappers that run a command (env, sudo, sh -c, xargs,
# ...). Quotes are stripped, short options are read inside clusters (-nm,
# -uf), and long options also by the abbreviations git accepts (--no-verif).
#
# Each command line is read twice and blocked if either reading blocks it:
# once split as written, and once with continued lines joined, redirections
# dropped and comments cut. A line with a $(...) or backtick substitution
# is read twice more with each substitution replaced by one word. No
# reading follows shell quoting, so quoted text can cause a false block, or
# hide a word from some of the readings.
#
# Advisory layer: this is a string filter, not a shell parser. It cannot see
# commands assembled at runtime (scripts, aliases, variables, exported
# config), literal forms it does not model can still get through, and it
# fails open without jq. Rulesets and CI are authoritative.
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
# so a checkout of main earlier in the line counts as being on main. A
# checkout that creates another branch returns to the branch checked out
# when the hook runs, which is never overridden the other way.
on_main=0

on_main_branch() {
  [ "$on_main" = 1 ] && return 0
  [ "$(git symbolic-ref --short -q HEAD 2>/dev/null)" = "main" ]
}

# abbrev_of TOKEN OPTION MIN: TOKEN is OPTION or a prefix of it at least MIN
# characters long. git accepts any unambiguous abbreviation of a long
# option, and MIN is at or below the shortest one git resolves.
abbrev_of() {
  [ "${#1}" -ge "$3" ] || return 1
  case "$2" in
  "$1"*) return 0 ;;
  esac
  return 1
}

# short_flag CLUSTER FLAG VALUED VALID: git would accept the short-option
# cluster (-nm) and it sets FLAG. The first option in VALUED takes the rest
# of the cluster as its value (-mn is -m with the message "n"); a letter
# outside VALID makes git reject the whole cluster before acting on it.
short_flag() {
  local s=${1#-} c found=1
  while [ -n "$s" ]; do
    c=${s:0:1}
    case "$4" in
    *"$c"*) ;;
    *) return 1 ;;
    esac
    [ "$c" = "$2" ] && found=0
    case "$3" in
    *"$c"*) return "$found" ;;
    esac
    s=${s:1}
  done
  return "$found"
}

# takes_next CLUSTER VALUED: the cluster ends in an option that takes the
# next word as its value (-o ci.skip, -uo ci.skip).
takes_next() {
  local s=${1#-} c
  while [ -n "$s" ]; do
    c=${s:0:1}
    case "$2" in
    *"$c"*)
      [ "${#s}" -eq 1 ]
      return
      ;;
    esac
    s=${s:1}
  done
  return 1
}

# check_ref_config KEY VALUE: config that changes which refs a push selects
# (a mirror remote, push refspecs, a push.default that pushes main), or an
# alias that can hide a blocked command. Shared by git -c, GIT_CONFIG_* and
# git config; KEY and VALUE are lowercase. upstream (tracking) pushes to the
# upstream, which is origin/main for a branch made from it.
check_ref_config() {
  case "$1" in
  alias.*) block "defining a git alias can hide a blocked command" ;;
  remote.*.mirror | remote.*.push) block "a mirror remote or push refspecs in config can push main" ;;
  push.default)
    case "$2" in
    matching | upstream | tracking) block "push.default=$2 can push main" ;;
    esac
    ;;
  esac
}

# check_config_pair OPTION KEY[=VALUE]: git -c and --config-env set config
# for one invocation. Only an explicit true keeps signing on; a --config-env
# value names an environment variable, so it is never trusted. A key
# without =VALUE is a boolean true.
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
  case "$kv" in
  *=*) check_ref_config "${kv%%=*}" "${kv#*=}" ;;
  *) check_ref_config "$kv" "" ;;
  esac
}

# GIT_CONFIG_PARAMETERS and GIT_CONFIG_COUNT/KEY_n/VALUE_n are the
# environment form of git -c and reach every git a command runs. One
# variable can carry several entries, so the whole segment is searched.
check_config_env() {
  local t s
  for t in "$@"; do
    case "$t" in
    GIT_CONFIG_PARAMETERS=* | GIT_CONFIG_COUNT=* | GIT_CONFIG_KEY_*=* | GIT_CONFIG_VALUE_*=*)
      s=$(lc "$*")
      case "$s" in
      *commit.gpgsign*) block "overriding commit signing through GIT_CONFIG_* variables" ;;
      *core.hookspath*) block "overriding core.hooksPath through GIT_CONFIG_* variables bypasses the repository git hooks" ;;
      *alias.*) block "defining a git alias through GIT_CONFIG_* variables can hide a blocked command" ;;
      *remote.*.mirror* | *remote.*.push* | *push.default*matching* | *push.default*upstream* | *push.default*tracking*)
        block "GIT_CONFIG_* variables changing which refs a push selects can push main"
        ;;
      esac
      return
      ;;
    esac
  done
}

# glob_names_main REFSPEC: the wildcard refspec writes main. That is its
# destination side, or the source side when there is no destination
# (SRC or SRC:).
glob_names_main() {
  local side=${1#+} name
  case "$side" in
  *:?*) side=${side#*:} ;;
  *:) side=${side%:} ;;
  esac
  for name in main refs/heads/main heads/main; do
    # The refspec side is a glob, so the pattern stays unquoted.
    # shellcheck disable=SC2254
    case $name in
    $side) return 0 ;;
    esac
  done
  return 1
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
    -C | --git-dir | --work-tree | --namespace | --exec-path | --attr-source)
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

  # AGENTS.md forbids these on every git command, not only commit/merge/push.
  for t in "${rest[@]}"; do
    case "$t" in
    --*)
      name=${t%%=*}
      abbrev_of "$name" --no-verify 6 && block "git $sub --no-verify skips the repository git hooks"
      abbrev_of "$name" --no-gpg-sign 6 && block "all commits must be SSH-signed (no --no-gpg-sign)"
      ;;
    esac
  done

  case "$sub" in
  commit)
    if [ "$has_trailer" = 1 ]; then
      block "Co-Authored-By trailers are not allowed in commit messages"
    fi
    for t in "${rest[@]}"; do
      case "$t" in
      --*) ;;
      -*)
        short_flag "$t" n FmcCtUSu qvseaipoznFmcCtUSu && block "git commit --no-verify skips the repository git hooks"
        ;;
      esac
    done
    ;;
  push)
    local nonopt=() value=0 isvalue
    for t in "${rest[@]}"; do
      isvalue=$value
      value=0
      case "$t" in
      --*)
        name=${t%%=*}
        if abbrev_of "$name" --force 5 || abbrev_of "$name" --force-with-lease 5 ||
          abbrev_of "$name" --force-if-includes 5; then
          block "force-pushing is not allowed"
        fi
        if abbrev_of "$name" --all 3 || abbrev_of "$name" --branches 3 || abbrev_of "$name" --mirror 3; then
          block "git push --all/--branches/--mirror also pushes main; push a single feature branch"
        fi
        if [ "$name" = "$t" ]; then
          if abbrev_of "$t" --push-option 5 || abbrev_of "$t" --repo 5 ||
            abbrev_of "$t" --receive-pack 5 || abbrev_of "$t" --exec 4; then
            value=1
          fi
        else
          case "${t#*=}" in
          main | refs/heads/main | heads/main | *:main | *:refs/heads/main | *:heads/main)
            block "pushing to main directly is not allowed; open a pull request"
            ;;
          esac
        fi
        ;;
      -*)
        short_flag "$t" f o vqdnfu46o && block "force-pushing is not allowed"
        takes_next "$t" o && value=1
        ;;
      +*) block "force-push refspecs (+...) are not allowed" ;;
      main | refs/heads/main | heads/main | *:main | *:refs/heads/main | *:heads/main)
        block "pushing to main directly is not allowed; open a pull request"
        ;;
      :) block "git push : pushes every matching branch, including main" ;;
      *\**)
        glob_names_main "$t" && block "a wildcard refspec that matches main pushes main"
        [ "$isvalue" = 1 ] || nonopt+=("$t")
        ;;
      *{*,*}* | *{*..*}*) block "brace-expanded push arguments can name main" ;;
      *) [ "$isvalue" = 1 ] || nonopt+=("$t") ;;
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
    local target="" created="" track=0 want=0 j=0
    while [ "$j" -lt "${#rest[@]}" ]; do
      t=${rest[$j]}
      j=$((j + 1))
      if [ "$want" = 1 ]; then
        created=$t
        want=0
        continue
      fi
      case "$t" in
      --)
        # Paths after -- restore files and leave the branch alone.
        [ "$j" -lt "${#rest[@]}" ] && return 0
        break
        ;;
      -b | -B | -c | -C | --orphan | --create | --force-create) want=1 ;;
      --orphan=* | --create=* | --force-create=*) created=${t#*=} ;;
      -[bBcC]?*) created=${t:2} ;;
      -t | --track | --track=*) track=1 ;;
      -) [ -n "$target" ] || target=$t ;;
      -*) ;;
      *) [ -n "$target" ] || target=$t ;;
      esac
    done
    if [ -n "$created" ]; then
      if [ "$created" = main ]; then on_main=1; else on_main=0; fi
    elif [ "$track" = 1 ]; then
      case "$target" in
      */main) on_main=1 ;;
      esac
    else
      case "$target" in
      main | - | @\{-*\}) on_main=1 ;;
      esac
    fi
    ;;
  config)
    if grep -qi 'commit\.gpgsign' <<<"$seg"; then
      case "$(lc "$seg")" in
      *false* | *" 0"* | *" no"* | *" off"* | *unset*) block "disabling commit signing (commit.gpgsign)" ;;
      esac
      # An empty value is false; stripped quotes would make it look like a read.
      case "$raw_seg" in
      *\"\"* | *\'\'*) block "disabling commit signing (commit.gpgsign set to an empty value)" ;;
      esac
    fi
    if grep -qi 'core\.hookspath' <<<"$seg"; then
      block "changing core.hooksPath bypasses the repository git hooks (use make setup)"
    fi
    case "$seg" in
    *remove-section* | *rename-section*)
      for t in "${rest[@]}"; do
        case "$(lc "$t")" in
        commit | core) block "removing or renaming the $t config section can turn off signing or the git hooks" ;;
        esac
      done
      ;;
    esac
    # Writes (KEY VALUE, or a write option or subcommand) go through the
    # same key checks as git -c. Reads and unsets stay allowed; the value of
    # an option such as --comment is skipped, so it cannot pass for --list.
    local keys=() read=0 write=0 unset=0 optval=0 k
    for t in "${rest[@]}"; do
      if [ "$optval" = 1 ]; then
        optval=0
        continue
      fi
      case "$t" in
      --comment | -f | --file | --blob | --type | --default | --value) optval=1 ;;
      --get | --get-all | --get-regexp | --get-urlmatch | --list | -l) read=1 ;;
      --unset | --unset-all) unset=1 ;;
      --add | --replace-all) write=1 ;;
      -*) ;;
      *) keys+=("$(lc "$t")") ;;
      esac
    done
    case "${keys[0]}" in
    get | list) read=1 ;;
    set) write=1 ;;
    unset) unset=1 ;;
    esac
    [ "$unset" = 1 ] && [ "$write" = 0 ] && read=1
    if [ "$read" = 0 ] && { [ "$write" = 1 ] || [ "${#keys[@]}" -ge 2 ]; }; then
      k=0
      while [ "$k" -lt "${#keys[@]}" ]; do
        check_ref_config "${keys[$k]}" "${keys[$((k + 1))]}"
        k=$((k + 1))
      done
    fi
    ;;
  send-pack)
    block "git send-pack pushes without the pre-push hook; use git push"
    ;;
  remote)
    for t in "${rest[@]}"; do
      case "$t" in
      --mirror*) block "a mirror remote (git remote --mirror) force-pushes every ref, including main" ;;
      esac
    done
    ;;
  esac
}

check_gh() {
  local pos=() t skip=0 admin=1
  for t in "$@"; do
    if [ "$skip" = 1 ]; then
      skip=0
      continue
    fi
    case "$t" in
    -R | --repo) skip=1 ;;
    --admin) admin=0 ;;
    --admin=*)
      case "$(lc "${t#--admin=}")" in
      false | f | 0) ;;
      *) admin=0 ;;
      esac
      ;;
    -*) ;;
    *) pos+=("$t") ;;
    esac
  done
  if [ "${pos[0]}" = pr ] && [ "${pos[1]}" = merge ] && [ "$admin" = 0 ]; then
    block "gh pr merge --admin bypasses the required status checks"
  fi
  if [ "${pos[0]}" = alias ] && [ "${pos[1]}" = set ] && [ "$admin" = 0 ]; then
    block "a gh alias carrying --admin can hide gh pr merge --admin"
  fi
}

# find_command WORD...: sets cmd_idx to the indexes of the command words to
# check. Variable assignments and shell keywords before the command are
# skipped. Behind a wrapper that runs a command, every later git or gh word
# is checked, so wrapper options and their values need no parsing (sudo -u
# git git push still reaches the second git).
find_command() {
  local words=("$@") i=0 t
  cmd_idx=()
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
    env | command | builtin | exec | eval | nohup | nice | time | timeout | sudo | doas | su | xargs | \
      sh | bash | zsh | dash | ksh | fish | busybox | script | stdbuf | setsid | ionice | flock | \
      unbuffer | chronic | strace | coproc | gtimeout | caffeinate | xcrun | arch | chrt | taskset | \
      watch | runuser | systemd-run | ssh)
      i=$((i + 1))
      while [ "$i" -lt "${#words[@]}" ]; do
        case "${words[$i]##*/}" in
        git | gh) cmd_idx+=("$i") ;;
        esac
        i=$((i + 1))
      done
      return
      ;;
    *)
      cmd_idx=("$i")
      return
      ;;
    esac
    i=$((i + 1))
  done
}

# scan MODE TEXT: splits TEXT on |, ;, &, backticks and parentheses (the
# latter catch $(...) command substitutions and subshells), strips quotes
# and backslashes, and checks every segment that runs git or gh. Splitting
# checks the command inside a substitution as its own segment, but cuts the
# words after the substitution off from their command; flatten_subst covers
# those. Mode "joined" also joins backslash-continued lines, cuts comments
# and drops redirections, keeping a word glued to one (-f>/dev/null). Mode
# "split" does none of that, so a quoted ">", "\" or "#" cannot hide a word
# from both readings.
scan() {
  local input=$2 t words skip
  on_main=0
  [ "$1" = joined ] && input=${input//\\$'\n'/ }
  while IFS= read -r raw_seg; do
    read -ra raw <<<"$raw_seg"
    words=()
    skip=0
    for t in "${raw[@]}"; do
      if [ "$1" = joined ]; then
        if [ "$skip" = 1 ]; then
          skip=0
          continue
        fi
        case "$t" in
        '#'*) break ;;
        esac
      fi
      t=${t//\$\"/\"}
      t=${t//\$\'/\'}
      t=${t//\"/}
      t=${t//\'/}
      t=${t//\\/}
      if [ "$1" = joined ]; then
        case "$t" in
        *[\<\>]*)
          case "$t" in
          *[\<\>]) skip=1 ;;
          esac
          t=${t%%[\<\>]*}
          case "$t" in
          '' | [0-9] | [0-9][0-9]) continue ;;
          esac
          ;;
        esac
      fi
      words+=("$t")
    done
    [ "${#words[@]}" -eq 0 ] && continue
    check_config_env "${words[@]}"
    find_command "${words[@]}"
    for i in "${cmd_idx[@]}"; do
      case "${words[$i]##*/}" in
      git) check_git "${words[@]:$((i + 1))}" ;;
      gh) check_gh "${words[@]:$((i + 1))}" ;;
      esac
    done
  done < <(printf '%s\n' "$input" | tr '|;&`()' '\n')
}

# flatten_subst TEXT: TEXT with each $(...) (nesting counted, across lines)
# and each backtick pair replaced by one word, so the words after it stay
# with their command (git commit -m "$(cat <<EOF ...)" --no-verify).
flatten_subst() {
  printf '%s' "$1" | awk 'BEGIN { RS = "\001"; ORS = "" }
  {
    depth = 0; tick = 0; out = ""; n = length($0)
    for (i = 1; i <= n; i++) {
      c = substr($0, i, 1)
      if (tick) { if (c == "`") tick = 0; continue }
      if (depth > 0) { if (c == "(") depth++; else if (c == ")") depth--; continue }
      if (c == "$" && substr($0, i + 1, 1) == "(") { depth = 1; i++; out = out "SUBST"; continue }
      if (c == "`") { tick = 1; out = out "SUBST"; continue }
      out = out c
    }
    print out
  }'
}

# A Co-Authored-By trailer can sit on a later line of a multi-line message
# or a heredoc, so git commit checks the whole command line, without the
# quotes and backslashes that can split the word. It is searched once here:
# searching per segment made the hook quadratic in the command length, and
# a hook that times out lets the command through.
has_trailer=0
if printf '%s' "$cmd" | tr -d "\"'\\\\" | grep -qi 'co-authored-by'; then
  has_trailer=1
fi

scan split "$cmd"
scan joined "$cmd"
case "$cmd" in
*\$\(* | *\`*)
  flat=$(flatten_subst "$cmd")
  scan split "$flat"
  scan joined "$flat"
  ;;
esac

exit 0
