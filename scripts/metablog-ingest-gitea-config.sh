#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# scripts/metablog-ingest-gitea-config.sh
# Ensure Gitea has ENABLE_PUSH_CREATE_USER=true and DEFAULT_BRANCH=main.
# Idempotent: skip restart if no changes were made.
#
# Used by: metablog-ingest.sh preflight
# Requires: SSH to root@192.168.1.200, lxc-attach to gitea LXC

set -euo pipefail

GITEA_HOST="${GITEA_HOST:-192.168.1.200}"
LXC_NAME="${LXC_NAME:-gitea}"
APP_INI="${APP_INI:-/var/lib/gitea/custom/conf/app.ini}"

log() { echo "[gitea-config] $*"; }
fail() { echo "[gitea-config] FAIL: $*" >&2; exit 1; }

# Verify we can reach the LXC
ssh "root@$GITEA_HOST" "lxc-info -n $LXC_NAME -s 2>/dev/null | grep -q RUNNING" \
  || fail "Gitea LXC '$LXC_NAME' is not running on $GITEA_HOST"

# Probe the app.ini path
if ! ssh "root@$GITEA_HOST" "lxc-attach -n $LXC_NAME -- test -f $APP_INI"; then
  alt=$(ssh "root@$GITEA_HOST" "lxc-attach -n $LXC_NAME -- find / -name app.ini -type f 2>/dev/null | grep -v proc | head -1" || true)
  [[ -n "$alt" ]] && APP_INI="$alt" || fail "app.ini not found in Gitea LXC"
  log "Using detected path: $APP_INI"
fi

# Check current state — fast-path skip if both keys already set correctly
current=$(ssh "root@$GITEA_HOST" "lxc-attach -n $LXC_NAME -- grep -E '^(ENABLE_PUSH_CREATE_USER|DEFAULT_BRANCH)\s*=' $APP_INI 2>/dev/null" || true)
if echo "$current" | grep -q "ENABLE_PUSH_CREATE_USER\s*=\s*true" \
   && echo "$current" | grep -q "DEFAULT_BRANCH\s*=\s*main"; then
  log "Already configured — no change."
  exit 0
fi

# Take a backup
ssh "root@$GITEA_HOST" "lxc-attach -n $LXC_NAME -- cp $APP_INI $APP_INI.bak.metablog-ingest.\$(date +%s)"

# Patch: ensure [repository] section has both keys
# Uses awk (no python3 required) to safely edit the INI file.
# Strategy:
#   - Track when we're inside [repository]
#   - Replace existing keys in-place if found
#   - Append missing keys before the next section header or EOF
ssh "root@$GITEA_HOST" "lxc-attach -n $LXC_NAME -- bash -s $APP_INI" <<'AWKEOF'
INI="$1"
TMP="$INI.tmp.$$"

awk '
BEGIN {
    in_repo = 0
    saw_push = 0
    saw_branch = 0
    need_push = "ENABLE_PUSH_CREATE_USER = true"
    need_branch = "DEFAULT_BRANCH = main"
}

# Detect section headers
/^\[/ {
    if (in_repo) {
        # Leaving [repository] — flush missing keys before new section
        if (!saw_push)  { print need_push;  saw_push = 1 }
        if (!saw_branch){ print need_branch; saw_branch = 1 }
        in_repo = 0
    }
    in_repo = (tolower($0) == "[repository]")
}

in_repo && /^[[:space:]]*ENABLE_PUSH_CREATE_USER[[:space:]]*=/ {
    print "ENABLE_PUSH_CREATE_USER = true"
    saw_push = 1
    next
}

in_repo && /^[[:space:]]*DEFAULT_BRANCH[[:space:]]*=/ {
    print "DEFAULT_BRANCH = main"
    saw_branch = 1
    next
}

{ print }

END {
    if (in_repo) {
        # EOF inside [repository]
        if (!saw_push)  { print need_push }
        if (!saw_branch){ print need_branch }
    } else if (!saw_push || !saw_branch) {
        # [repository] section was never found — append it
        if (!saw_push || !saw_branch) {
            print ""
            print "[repository]"
            if (!saw_push)  { print need_push }
            if (!saw_branch){ print need_branch }
        }
    }
}
' "$INI" > "$TMP" && mv "$TMP" "$INI"
echo "patched"
AWKEOF

# Restart Gitea
ssh "root@$GITEA_HOST" "lxc-attach -n $LXC_NAME -- systemctl restart gitea"
sleep 3
status=$(ssh "root@$GITEA_HOST" "lxc-attach -n $LXC_NAME -- systemctl is-active gitea" 2>/dev/null || true)
[[ "$status" == "active" ]] || fail "Gitea did not come back up after restart (status: $status)"

log "Gitea reconfigured + restarted. ENABLE_PUSH_CREATE_USER=true, DEFAULT_BRANCH=main."
