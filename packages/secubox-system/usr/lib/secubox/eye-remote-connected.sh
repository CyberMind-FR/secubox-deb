#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
#
# SecuBox Eye Remote — USB OTG connect handler.
# Called by udev when a Pi RNDIS gadget (MAC 02:fb:00:00:*) is plugged in.
# Enslaves the kernel-named interface (usb0/usb1/…) into the eye-br0 bridge
# managed by systemd-networkd (05-eye-br0.netdev + 10-eye-br0.network).
#
# The bridge owns the host IP 10.55.0.1/24, so multiple gadgets can coexist
# without duplicate-address races. Per-Pi L3 addressing is the Round image's
# responsibility — see remote-ui/round/MULTI-GADGET.md.

set -euo pipefail

IFACE="${INTERFACE:-${1:-}}"
BRIDGE="eye-br0"
PEER_IP="10.55.0.2"

log() { logger -t "secubox-eye-remote" "$*"; }

if [[ -z "$IFACE" ]]; then
    log "ERROR: no interface name (\$INTERFACE / \$1)"
    exit 1
fi

log "Eye Remote connect: $IFACE"

# Wait for the kernel netdev to settle (rndis_host probing can take ~1s)
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [[ -e "/sys/class/net/$IFACE" ]] && break
    sleep 0.2
done

if [[ ! -e "/sys/class/net/$IFACE" ]]; then
    log "ERROR: interface $IFACE not found"
    exit 1
fi

# Wait for the bridge — networkd may still be bringing it up on cold boot.
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [[ -e "/sys/class/net/$BRIDGE" ]] && break
    sleep 0.2
done

if [[ ! -e "/sys/class/net/$BRIDGE" ]]; then
    log "WARN: bridge $BRIDGE missing — falling back to point-to-point on $IFACE"
    ip addr flush dev "$IFACE" 2>/dev/null || true
    ip addr add 10.55.0.1/24 dev "$IFACE" 2>/dev/null || true
    ip link set "$IFACE" up
else
    # Drop any stray IP on the gadget iface — the bridge owns L3.
    ip addr flush dev "$IFACE" 2>/dev/null || true
    ip link set "$IFACE" master "$BRIDGE"
    ip link set "$IFACE" up
    log "Enslaved $IFACE into $BRIDGE"
fi

# Notify the API (best-effort; the service may not be running yet on boot)
if command -v curl >/dev/null 2>&1; then
    curl --max-time 2 -s -X POST \
        "http://127.0.0.1:8000/api/v1/system/eye-remote/connected" \
        -H "Content-Type: application/json" \
        -d "{\"interface\": \"$IFACE\", \"bridge\": \"$BRIDGE\", \"peer_ip\": \"$PEER_IP\"}" \
        >/dev/null 2>&1 || true
fi

log "Eye Remote ready: $IFACE on $BRIDGE (peer $PEER_IP)"
