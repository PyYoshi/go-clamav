@AGENTS.md

## Claude Code specifics

- Project hooks (`.claude/settings.json`) enforce the EICAR policy and git
  rules in-session; the Stop hook blocks once when Go sources changed but
  `make verify` has not passed against them. Do not work around a blocked
  action — fix the cause or ask the user.
- Skills: `/pr-flow` (feature branch → PR → CodeRabbit → merge commit) and
  `/release` (CHANGELOG cut + signed tag + GitHub release; explicit
  invocation only).
