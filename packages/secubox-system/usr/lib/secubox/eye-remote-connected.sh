#!/usr/bin/env bash
# SecuBox Eye Remote Connected Handler
# Called by udev when Pi Zero W Eye Remote is connected via USB OTG
# CyberMind - https://cybermind.fr
set -euo pipefail

IFACE="${INTERFACE:-eye-remote}"
HOST_IP="10.55.0.1"
PEER_IP="10.55.0.2"
NETMASK="30"

log() {
    logger -t "secubox-eye-remote" "$*"
    echo "[eye-remote] $*"
}

log "Eye Remote connected: $IFACE"

# Wait for interface to be ready
sleep 1

# Configure host side of OTG link
if ip link show "$IFACE" &>/dev/null; then
    # Set IP address (host side)
    ip addr flush dev "$IFACE" 2>/dev/null || true
    ip addr add "${HOST_IP}/${NETMASK}" dev "$IFACE"
    ip link set "$IFACE" up

    log "Interface $IFACE configured: ${HOST_IP}/${NETMASK}"

    # Add route to Eye Remote
    ip route add "${PEER_IP}/32" dev "$IFACE" 2>/dev/null || true

    # Enable forwarding for this interface
    echo 1 > /proc/sys/net/ipv4/conf/"$IFACE"/forwarding 2>/dev/null || true

    # Notify SecuBox API that Eye Remote is connected
    if command -v curl &>/dev/null; then
        curl -s -X POST "http://127.0.0.1:8000/api/v1/system/eye-remote/connected" \
            -H "Content-Type: application/json" \
            -d "{\"interface\": \"$IFACE\", \"peer_ip\": \"$PEER_IP\"}" \
            2>/dev/null || true
    fi

    log "Eye Remote ready at ${PEER_IP}"
else
    log "ERROR: Interface $IFACE not found"
    exit 1
fi
