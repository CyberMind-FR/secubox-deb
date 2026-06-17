#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: WAF inspector watchdog (#624)
# Auto-recover the mitmproxy LXC if its inspector port is down for MAXFAIL
# consecutive checks. Rate-limited by COOLDOWN to avoid restart flap. The whole
# point: an inspector crash becomes a ~3-minute auto-recovery instead of a
# multi-hour board-wide 503.
set -uo pipefail

readonly HOST="${SECUBOX_WAF_HOST:-10.100.0.60}"
readonly PORT="${SECUBOX_WAF_PORT:-8080}"
readonly CTN="${SECUBOX_WAF_CTN:-mitmproxy}"
readonly STATE="/run/secubox-waf-watchdog.state"
readonly MAXFAIL="${SECUBOX_WAF_MAXFAIL:-3}"
readonly COOLDOWN="${SECUBOX_WAF_COOLDOWN:-600}"

now="$(date +%s)"
fails=0
last=0
if [ -f "$STATE" ]; then
    read -r fails last < "$STATE" 2>/dev/null || true
fi
[[ "$fails" =~ ^[0-9]+$ ]] || fails=0
[[ "$last"  =~ ^[0-9]+$ ]] || last=0

# Healthy → reset the failure counter and exit.
if timeout 4 bash -c "echo >/dev/tcp/$HOST/$PORT" 2>/dev/null; then
    echo "0 $last" > "$STATE"
    exit 0
fi

fails=$((fails + 1))
logger -t secubox-waf-watchdog "inspector $HOST:$PORT DOWN (fail $fails/$MAXFAIL)"

if [ "$fails" -ge "$MAXFAIL" ] && [ $((now - last)) -ge "$COOLDOWN" ]; then
    logger -t secubox-waf-watchdog "auto-recovering container $CTN"
    timeout 45 lxc-stop -n "$CTN" -k 2>/dev/null || true
    timeout 45 lxc-start -n "$CTN" -d 2>/dev/null || true
    echo "0 $now" > "$STATE"
else
    echo "$fails $last" > "$STATE"
fi
