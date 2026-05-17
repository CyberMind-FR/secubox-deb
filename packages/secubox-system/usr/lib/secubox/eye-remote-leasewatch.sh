#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
#
# SecuBox-Deb :: eye-remote dnsmasq dhcp-script hook (issue #158)
# Called by dnsmasq on every lease lifecycle event:
#     $1 = action  (add | old | del)
#     $2 = MAC
#     $3 = IP
#     $4 = hostname (optional, "*" if absent)
#
# Side effects:
#   - On `add` for a never-before-seen MAC: append a stable reservation
#     to /etc/secubox/eye-remote/reservations.conf and reload dnsmasq.
#   - Always: POST a notification to the eye-remote API on loopback.
set -euo pipefail

action="${1:-}"
mac="${2:-}"
ip="${3:-}"
hostname="${4:-}"
[[ "$hostname" == "*" ]] && hostname=""

RES_FILE="${SECUBOX_EYE_RESERVATIONS_FILE:-/etc/secubox/eye-remote/reservations.conf}"
LEASE_TIME="${SECUBOX_EYE_LEASE_TIME:-24h}"
API_URL="${SECUBOX_EYE_API_URL:-http://127.0.0.1:8000/api/v1/eye-remote/lease-events}"
FIND_SERIAL="${SECUBOX_EYE_FIND_SERIAL:-/usr/lib/secubox/eye-remote-find-usb-serial}"

log() { logger -t secubox-eye-leasewatch "$*" 2>/dev/null || true; }

derive_hostname() {
    local m="$1"
    if [[ -n "$hostname" ]]; then
        echo "$hostname"
        return
    fi
    if [[ -x "$FIND_SERIAL" ]]; then
        local serial
        if serial=$("$FIND_SERIAL" "$m" 2>/dev/null); then
            echo "eye-$serial"
            return
        fi
    fi
    # Fallback: drop "02:" prefix from the MAC and strip remaining colons.
    # 02:fb:00:00:11:03 → eye-fb00001103
    local stripped=${m#*:}
    echo "eye-${stripped//:/}"
}

ensure_reservation() {
    local m="$1" i="$2" h="$3"
    if [[ ! -f "$RES_FILE" ]]; then
        install -D -m 0644 /dev/null "$RES_FILE"
    fi
    if grep -qE "^dhcp-host=${m}," "$RES_FILE"; then
        log "reservation already exists for $m, leaving alone"
        return
    fi
    # Ensure trailing newline before appending
    if [[ -s "$RES_FILE" ]]; then
        local last_char
        last_char=$(tail -c1 "$RES_FILE")
        if [[ "$last_char" != $'\n' ]]; then
            printf '\n' >> "$RES_FILE"
        fi
    fi
    printf 'dhcp-host=%s,%s,%s,%s\n' "$m" "$i" "$h" "$LEASE_TIME" >> "$RES_FILE"
    log "appended reservation: $m -> $i ($h)"
    if [[ -z "${SECUBOX_EYE_SKIP_RELOAD:-}" ]]; then
        systemctl reload secubox-eye-remote-dhcp.service || true
    fi
}

notify_api() {
    [[ -n "${SECUBOX_EYE_SKIP_API:-}" ]] && return 0
    command -v curl >/dev/null 2>&1 || return 0
    curl --max-time 2 -s -X POST "$API_URL" \
        -H "Content-Type: application/json" \
        -d "$(printf '{"action":"%s","mac":"%s","ip":"%s","hostname":"%s"}' \
              "$action" "$mac" "$ip" "$hostname")" \
        >/dev/null 2>&1 || true
}

case "$action" in
    add)
        host=$(derive_hostname "$mac")
        ensure_reservation "$mac" "$ip" "$host"
        ;;
    old|del)
        # Phase 1: events are reported only; Phase 2 may rotate or expire.
        :
        ;;
    *)
        log "unknown action: $action (ignored)"
        ;;
esac

notify_api
