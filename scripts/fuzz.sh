#!/usr/bin/env bash
# Runs the short fuzzing pass over internal/proto.
#
# `go test` fuzzes one target per invocation, so each target gets its own
# run. Two properties this script exists to guarantee:
#
#   - Budgets are per target, not shared. FuzzParseScanResponse enforces
#     "unknown never means clean" (AGENTS.md invariant 2) and keeps the
#     budget it had before the reader targets were added; splitting one
#     budget across three targets would have weakened that guard.
#   - A renamed or deleted target fails loudly. `go test -fuzz` prints
#     "no fuzz tests to fuzz" and exits 0 when the pattern matches
#     nothing, so the pass would silently fuzz nothing. Each name is
#     checked against `go test -list` first.
#
# Usage: fuzz.sh [package]   (default: ./internal/proto/)

set -euo pipefail

pkg="${1:-./internal/proto/}"

# target:seconds
targets=(
  "FuzzParseScanResponse:30"
  "FuzzReadLine:10"
  "FuzzReadBlock:10"
)

available="$(go test -list='^Fuzz' "$pkg")"

for entry in "${targets[@]}"; do
  name="${entry%%:*}"
  seconds="${entry##*:}"
  if ! grep -qx "$name" <<<"$available"; then
    echo "fuzz.sh: target $name not found in $pkg (renamed or removed?)" >&2
    exit 1
  fi
  echo "fuzz.sh: $name for ${seconds}s"
  go test -run='^$' -fuzz="^${name}\$" -fuzztime="${seconds}s" "$pkg"
done
