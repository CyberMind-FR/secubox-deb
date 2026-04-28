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

INTERFACE="${INTERFACE:-secubox-eye}"
HOST_IP="10.55.0.1"
NETMASK="30"
PEER_IP="10.55.0.2"

LOG_TAG="secubox-eye-network"

log() {
    logger -t "$LOG_TAG" "$*"
    echo "[$(date '+%H:%M:%S')] $*"
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

        log "Interface $INTERFACE configured, peer should be at $PEER_IP"

        # Optional: notify SecuBox API
        # curl -s -X POST http://localhost:8000/api/v1/remote-ui/connected \
        #     -H "Content-Type: application/json" \
        #     -d '{"transport":"otg","peer_ip":"'"$PEER_IP"'"}' || true
        ;;

    down)
        log "Removing $INTERFACE configuration"
        ip addr del "$HOST_IP/$NETMASK" dev "$INTERFACE" 2>/dev/null || true
        ;;

    *)
        echo "Usage: $0 up|down"
        exit 1
        ;;
esac
