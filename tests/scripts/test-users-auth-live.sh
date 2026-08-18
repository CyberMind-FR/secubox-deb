#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# Live smoke: verify auth rework against the canonical Hub.
# Usage: bash tests/scripts/test-users-auth-live.sh [<host>]
#
# Pre-flight: this assumes the secubox-users and secubox-auth packages have been
# deployed to the board AND that admin's password has been cleared (via
# `usersctl clear-password admin` over SSH) so the must_change_password flow
# triggers. The script restores any clobbered users.json/sessions.json on exit.
set -euo pipefail

HOST="${1:-admin.gk2.secubox.in}"
BOARD_SSH="${BOARD_SSH:-root@192.168.1.200}"
SNAP=$(mktemp -d)
trap 'rm -rf "$SNAP"' EXIT

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
log()   { printf '[smoke] %s\n' "$*"; }

log "1. Snapshot users.json + sessions.json"
ssh "$BOARD_SSH" cat /etc/secubox/users.json > "$SNAP/users.json"
ssh "$BOARD_SSH" cat /var/lib/secubox/auth/sessions.json > "$SNAP/sessions.json" 2>/dev/null || echo "[]" > "$SNAP/sessions.json"

restore() {
    log "Restoring snapshot…"
    ssh "$BOARD_SSH" "cat > /etc/secubox/users.json" < "$SNAP/users.json"
    ssh "$BOARD_SSH" "cat > /var/lib/secubox/auth/sessions.json" < "$SNAP/sessions.json" 2>/dev/null || true
}
trap 'restore; rm -rf "$SNAP"' EXIT

log "2. Clear admin password to trigger must_change_password flow"
ssh "$BOARD_SSH" 'usersctl clear-password admin'

log "3. Login with empty password should yield setup_token"
RESP=$(curl -sk --resolve "$HOST:443:192.168.1.200" \
    -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":""}' \
    "https://$HOST/api/v1/auth/login")
echo "$RESP" | grep -q setup_required || { red "FAIL: no setup_token. Response: $RESP"; exit 1; }
SETUP_TOK=$(echo "$RESP" | jq -r .setup_token)
green "  setup_token issued"

log "4. Set password"
curl -sk --resolve "$HOST:443:192.168.1.200" \
    -H "Authorization: Bearer $SETUP_TOK" \
    -H 'Content-Type: application/json' \
    -d '{"new_password":"SmokePass!42xy"}' \
    "https://$HOST/api/v1/auth/set-password" | jq -e .ok > /dev/null
green "  password set"

log "5. Login again → expect enrollment_required (admin)"
RESP=$(curl -sk --resolve "$HOST:443:192.168.1.200" \
    -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":"SmokePass!42xy"}' \
    "https://$HOST/api/v1/auth/login")
echo "$RESP" | grep -q enrollment_required || { red "FAIL: no enrollment_required. Response: $RESP"; exit 1; }
green "  enrollment_required returned"

log "6. Disable admin via usersctl → next login must fail"
ssh "$BOARD_SSH" 'usersctl disable admin'
HTTP=$(curl -sk -o /dev/null -w "%{http_code}" --resolve "$HOST:443:192.168.1.200" \
    -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":"SmokePass!42xy"}' \
    "https://$HOST/api/v1/auth/login")
[ "$HTTP" = "401" ] || { red "FAIL: disabled admin got HTTP $HTTP"; exit 1; }
green "  disabled admin → 401 ✓"

log "7. Re-enable admin"
ssh "$BOARD_SSH" 'usersctl enable admin'

green "OK — auth rework smoke passes. Snapshot will be restored on exit."
