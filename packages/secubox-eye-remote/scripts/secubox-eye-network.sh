#!/bin/bash
# ==============================================================================
# SecuBox Eye Remote - Host Network Configuration Script
# Called by udev when Pi Zero USB gadget is connected/disconnected
#
# Usage: secubox-eye-network.sh up|down
#
# CyberMind - https://cybermind.fr
# ==============================================================================
set -euo pipefail

# Find the usb0/usb1 interface created by gadget
INTERFACE="${INTERFACE:-usb0}"
HOST_IP="10.55.0.1"
NETMASK="24"
PEER_IP="10.55.0.2"

LOG_TAG="secubox-eye-network"

log() {
    logger -t "$LOG_TAG" "$*"
}

case "${1:-}" in
    up)
        log "Configuring $INTERFACE (Host: $HOST_IP/$NETMASK)"

        # Wait for interface to be ready
        for i in {1..10}; do
            if ip link show "$INTERFACE" &>/dev/null; then
                break
            fi
            sleep 0.5
        done

        # Configure IP
        ip link set "$INTERFACE" up
        ip addr add "$HOST_IP/$NETMASK" dev "$INTERFACE" 2>/dev/null || true

        log "Interface $INTERFACE configured, peer at $PEER_IP"

        # Notify SecuBox API
        curl -s --unix-socket /run/secubox/eye-remote.sock \
            -X POST "http://localhost/api/v1/eye-remote/connected?peer_ip=$PEER_IP" \
            2>/dev/null || true
        ;;

    down)
        log "Removing $INTERFACE configuration"
        ip addr del "$HOST_IP/$NETMASK" dev "$INTERFACE" 2>/dev/null || true

        # Notify SecuBox API
        curl -s --unix-socket /run/secubox/eye-remote.sock \
            -X POST "http://localhost/api/v1/eye-remote/disconnected" \
            2>/dev/null || true
        ;;

    *)
        log "Usage: $0 up|down"
        exit 1
        ;;
esac
