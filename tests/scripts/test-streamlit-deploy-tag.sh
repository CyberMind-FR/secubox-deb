#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# tests/scripts/test-streamlit-deploy-tag.sh
# End-to-end smoke for streamlitctl deploy --from-gitea --tag + rollback.
# Canary: yijing.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$REPO/scripts/lib/test-helpers.sh"

CANARY="${CANARY:-yijing}"
LXC_HOST="${LXC_HOST:-192.168.1.200}"

log_step() { echo "[deploy-test step $1] $2"; }

# Step 1: Confirm canary exists on Gitea at v1.0.0
log_step 1 "canary exists in Gitea at v1.0.0"
tag_sha=$(ssh "root@$LXC_HOST" "GIT_SSH_COMMAND='ssh -p 2222 -o BatchMode=yes' \
  git ls-remote --tags ssh://gitea@gitea.gk2.secubox.in:2222/gandalf/streamlit-$CANARY.git v1.0.0 2>/dev/null | awk '{print \$1}'" \
  | tr -d '[:space:]')
[[ -n "$tag_sha" ]] || { echo "FAIL: canary $CANARY has no v1.0.0 tag on Gitea"; exit 1; }
pass "v1.0.0 sha: $tag_sha"

# Step 2: Deploy --from-gitea --tag v1.0.0
log_step 2 "deploy --from-gitea --tag v1.0.0"
ssh "root@$LXC_HOST" "/usr/sbin/streamlitctl deploy $CANARY --from-gitea --tag v1.0.0" 2>&1 | tail -3

# Step 3: Verify .deploy.json
log_step 3 ".deploy.json present + correct tag"
tag_in_json=$(ssh "root@$LXC_HOST" "cat /srv/streamlit/apps/$CANARY/.deploy.json 2>/dev/null | grep -oE '\"tag\": *\"[^\"]*\"' | head -1 | sed 's/.*\"tag\": *\"\\([^\"]*\\)\".*/\\1/'")
assert_eq "v1.0.0" "$tag_in_json" ".deploy.json tag"

# Step 4: Verify API surfaces current_tag (if API is up — best-effort)
log_step 4 "API current_tag (best-effort)"
api_tag=$(ssh "root@$LXC_HOST" "curl -s --unix-socket /run/secubox/streamlit.sock http://x/apps 2>/dev/null | jq -r --arg n '$CANARY' '.apps[] | select(.name==\$n) | .current_tag' 2>/dev/null" | tail -1)
if [[ "$api_tag" == "v1.0.0" ]]; then
  pass "API current_tag for $CANARY is v1.0.0"
else
  echo "WARN: API current_tag for $CANARY is '$api_tag' (cache may be stale or API not refreshed yet). Not failing — this is best-effort. The .deploy.json gate (step 3) is authoritative."
fi

# Step 5: Backup directory exists
log_step 5 "backup directory exists"
backup_count=$(ssh "root@$LXC_HOST" "ls -d /srv/streamlit/apps/$CANARY.bak.* 2>/dev/null | wc -l")
[[ "$backup_count" -ge 1 ]] || { echo "FAIL: no backup dir for $CANARY"; exit 1; }
pass "$backup_count backup(s) present"

# Step 6: Rollback
log_step 6 "rollback"
ssh "root@$LXC_HOST" "/usr/sbin/streamlitctl rollback $CANARY" 2>&1 | tail -3

# After rollback: the latest .bak.* should have become current, and a
# <app>.bak.rolledback.<ts> sentinel should exist (carrying the previous current).
sentinel_count=$(ssh "root@$LXC_HOST" "ls -d /srv/streamlit/apps/$CANARY.bak.rolledback.* 2>/dev/null | wc -l")
[[ "$sentinel_count" -ge 1 ]] || { echo "FAIL: no rolledback sentinel for $CANARY"; exit 1; }
pass "rollback produced rolledback sentinel"

pass "all deploy/rollback checks passed"
