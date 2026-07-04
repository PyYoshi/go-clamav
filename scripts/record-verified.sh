#!/usr/bin/env bash
# Records the current Go source state digest as "verified". Run only as the
# final step of `make verify` — the recorded digest is the harness's proof
# that lint and tests passed against exactly these sources.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

harness_dir="$(git rev-parse --git-dir)/harness"
mkdir -p "$harness_dir"
./scripts/go-state-hash.sh >"$harness_dir/verified"
