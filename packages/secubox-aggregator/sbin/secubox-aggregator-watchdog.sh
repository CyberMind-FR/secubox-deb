#!/bin/bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
#
# SecuBox-Deb :: secubox-aggregator-watchdog
#
# Auto-heal the in-process aggregator — the hub/auth/menu single point of
# failure. Under a host load spike its shared event loop can wedge and its
# socket stops answering, taking down the navbar, login and service status
# board-wide (incident 2026-06-24). Probe the socket; if /api/v1/hub/public/menu
# stops answering for N consecutive checks, restart the service. Idempotent,
# safe to run on a timer.
set -uo pipefail
readonly MODULE="secubox-aggregator-watchdog"
readonly VERSION="1.0"

SOCK="/run/secubox/aggregator.sock"
# State lives in /run (root-owned), NOT the shared sticky /run/secubox: that dir
# is 1777 and a stale secubox-owned file there can't be overwritten by this
# (CSPN-hardened, CAP_DAC_OVERRIDE-less) root — which would silently freeze the
# streak counter and stop the watchdog ever triggering.
STATE="/run/secubox-aggregator-watchdog.fails"
FAIL_THRESHOLD="${SECUBOX_AGG_WD_THRESHOLD:-2}"
TIMEOUT="${SECUBOX_AGG_WD_TIMEOUT:-12}"

# No socket yet (service still starting / not migrated) → nothing to heal.
[ -S "$SOCK" ] || exit 0

code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT" \
        --unix-socket "$SOCK" http://localhost/api/v1/hub/public/menu 2>/dev/null || echo 000)

if [ "$code" = "200" ]; then
    echo 0 > "$STATE" 2>/dev/null || true
    exit 0
fi

n=$(( $(cat "$STATE" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$STATE" 2>/dev/null || true
logger -t "$MODULE" "aggregator probe failed (code=$code, streak=$n/$FAIL_THRESHOLD)"

if [ "$n" -ge "$FAIL_THRESHOLD" ]; then
    logger -t "$MODULE" "restarting secubox-aggregator (auto-heal)"
    systemctl restart secubox-aggregator.service
    echo 0 > "$STATE" 2>/dev/null || true
fi
exit 0
