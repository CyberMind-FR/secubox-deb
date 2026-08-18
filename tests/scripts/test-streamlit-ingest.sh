#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# tests/scripts/test-streamlit-ingest.sh
# Smoke test for the Streamlit → Gitea ingest pipeline.
# Runs against the live Gitea — NOT a unit test.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$REPO/scripts/lib/test-helpers.sh"

GITEA_HOST="${GITEA_HOST:-gitea.gk2.secubox.in}"
GITEA_SSH_PORT="${GITEA_SSH_PORT:-2222}"
GITEA_SSH_USER="${GITEA_SSH_USER:-gitea}"
REPORT="$REPO/output/streamlit-ingest-report.json"

log_step() { echo "[smoke step $1] $2"; }

# Step 1: Dry-run, --limit 3
log_step 1 "dry-run --limit 3"
bash "$REPO/scripts/streamlit-ingest.sh" --dry-run --limit 3 >/dev/null 2>&1
total=$(jq '.total' "$REPORT")
assert_eq "3" "$total" "dry-run total"

# Step 2: Real run, --limit 3
log_step 2 "live --limit 3"
bash "$REPO/scripts/streamlit-ingest.sh" --limit 3 >/dev/null 2>&1 || {
  echo "FAIL: live run errored. See $REPO/output/streamlit-ingest.log"
  tail -20 "$REPO/output/streamlit-ingest.log"
  exit 1
}
ok=$(jq '.by_status.ok + .by_status.skip' "$REPORT")
if [[ "$ok" -lt 3 ]]; then
  echo "FAIL: expected >=3 ok+skip, got $ok"
  jq . "$REPORT"
  exit 1
fi
pass "live --limit 3 produced $ok ok+skip apps"

# Step 3: Re-run — idempotent (all should skip)
log_step 3 "idempotent re-run"
bash "$REPO/scripts/streamlit-ingest.sh" --limit 3 >/dev/null 2>&1
skip=$(jq '.by_status.skip' "$REPORT")
assert_eq "3" "$skip" "all 3 should skip-already-current on re-run"

# Step 4: Verify on Gitea side via SSH ls-remote
log_step 4 "git ls-remote round-trip"
first_app=$(jq -r '.apps | to_entries[0].key' "$REPORT")
remote_head=$(ssh root@192.168.1.200 "GIT_SSH_COMMAND='ssh -p $GITEA_SSH_PORT -o BatchMode=yes -o StrictHostKeyChecking=accept-new' \
  git ls-remote ssh://$GITEA_SSH_USER@$GITEA_HOST:$GITEA_SSH_PORT/gandalf/streamlit-$first_app.git main 2>/dev/null | awk '{print \$1}'" \
  | tr -d '[:space:]')
[[ -n "$remote_head" ]] || { echo "FAIL: ls-remote returned no HEAD for $first_app"; exit 1; }
pass "remote HEAD for $first_app is $remote_head"

# Step 5: Verify tag v1.0.0 exists
log_step 5 "tag v1.0.0 exists"
tag_sha=$(ssh root@192.168.1.200 "GIT_SSH_COMMAND='ssh -p $GITEA_SSH_PORT -o BatchMode=yes' \
  git ls-remote --tags ssh://$GITEA_SSH_USER@$GITEA_HOST:$GITEA_SSH_PORT/gandalf/streamlit-$first_app.git v1.0.0 2>/dev/null | awk '{print \$1}'" \
  | tr -d '[:space:]')
[[ -n "$tag_sha" ]] || { echo "FAIL: v1.0.0 tag not found for $first_app"; exit 1; }
pass "tag v1.0.0 for $first_app is $tag_sha"

pass "all smoke checks passed"
