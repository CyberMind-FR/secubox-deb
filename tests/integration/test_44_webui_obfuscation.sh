#!/bin/bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# tests/integration/test_44_webui_obfuscation.sh
# End-to-end test for issue #44 — run on the board (or a VM that mirrors it).
#
# Pre-requisites:
#   - secubox-defaults, secubox-haproxy installed
#   - /etc/default/secubox with SECUBOX_HOSTNAME and SECUBOX_DOMAIN_SUFFIX set
#   - secubox-haproxy.service running
#
# Exit codes:
#   0  all probes succeeded
#   1  one or more probes failed (rollback performed)
#   2  pre-flight check failed (no changes made)
set -euo pipefail

LOG() { echo "[$(date '+%F %T')] $*" >&2; }
FAIL() { LOG "FAIL: $*"; exit 1; }

# Pre-flight
[[ -f /etc/default/secubox ]] || { LOG "missing /etc/default/secubox"; exit 2; }
# shellcheck source=/dev/null
. /etc/default/secubox
[[ -n "${SECUBOX_HOSTNAME:-}" ]] || { LOG "SECUBOX_HOSTNAME unset"; exit 2; }
ADMIN="admin.${SECUBOX_HOSTNAME}.${SECUBOX_DOMAIN_SUFFIX:-secubox.in}"
LOG "Canonical admin URL: https://$ADMIN/"

# Snapshot
TS=$(date +%s)
SNAP_HA="/etc/haproxy/haproxy.cfg.bak.$TS-test44"
SNAP_NX="/etc/nginx/sites-available/secubox-local.bak.$TS-test44"
cp -p /etc/haproxy/haproxy.cfg "$SNAP_HA"
cp -p /etc/nginx/sites-available/secubox-local "$SNAP_NX" 2>/dev/null || true

restore() {
    LOG "Restoring snapshots"
    cp -p "$SNAP_HA" /etc/haproxy/haproxy.cfg
    [[ -f "$SNAP_NX" ]] && cp -p "$SNAP_NX" /etc/nginx/sites-available/secubox-local
    systemctl reload haproxy nginx || true
}
trap 'restore' ERR

# 1. Render nginx + regen HAProxy
LOG "Render + regen"
/usr/local/bin/secubox-render-nginx-webui
/usr/local/bin/secubox-haproxy-regen-safe

# 2. Positive probe
LOG "Probe https://$ADMIN/"
TITLE=$(curl -ski "https://$ADMIN/?cb=$RANDOM" | grep -oE '<title>[^<]+</title>' | head -1)
[[ "$TITLE" == *"SecuBox Control Center"* ]] || FAIL "admin URL not serving WebUI ($TITLE)"

# 3. Negative probe: gk2.secubox.in (no admin.) should NOT be WebUI
LOG "Probe https://${SECUBOX_HOSTNAME}.${SECUBOX_DOMAIN_SUFFIX:-secubox.in}/ (should NOT serve WebUI)"
BODY=$(curl -sk "https://${SECUBOX_HOSTNAME}.${SECUBOX_DOMAIN_SUFFIX:-secubox.in}/" || true)
echo "$BODY" | grep -q "SecuBox Control Center" && FAIL "non-admin host served WebUI"

# 4. LAN-direct still works
LOG "Probe LAN direct https://192.168.1.200:9443/"
TITLE=$(curl -ski "https://192.168.1.200:9443/?cb=$RANDOM" | grep -oE '<title>[^<]+</title>' | head -1)
[[ "$TITLE" == *"SecuBox Control Center"* ]] || FAIL "LAN-direct broken ($TITLE)"

# 5. Random admin.* should be rejected
LOG "Probe https://admin.fake.secubox.in/ (should NOT serve WebUI)"
BODY=$(curl -sk -H "Host: admin.fake.secubox.in" "https://192.168.1.200/" || true)
echo "$BODY" | grep -q "SecuBox Control Center" && FAIL "random admin.X served WebUI"

# 6. Regression spot-checks
LOG "Regression spot-checks"
for d in cpf.gk2.secubox.in arm.gk2.secubox.in lldh.ganimed.fr pub.gk2.secubox.in werdl.gk2.secubox.in 3d.gk2.secubox.in; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$d/?cb=$RANDOM")
    [[ "$code" == "200" ]] || FAIL "regression on $d (HTTP $code)"
done

trap - ERR
LOG "ALL TESTS PASSED — snapshots kept at $SNAP_HA and $SNAP_NX for forensics"
