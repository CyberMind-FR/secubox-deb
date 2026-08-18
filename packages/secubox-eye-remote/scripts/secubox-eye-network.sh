#!/bin/bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# ==============================================================================
# SecuBox Eye Remote - Host Network Configuration Script
# Called by udev/systemd when Pi Zero USB gadget is connected/disconnected
#
# Usage: secubox-eye-network.sh up|down|status
#
# CyberMind - https://cybermind.fr
# ==============================================================================

# Find usb interface - prefer usb0, fallback to finding by MAC
find_interface() {
    # Check if INTERFACE is set (from udev)
    if [[ -n "${INTERFACE:-}" ]] && ip link show "$INTERFACE" &>/dev/null; then
        echo "$INTERFACE"
        return 0
    fi

    # Look for interface with Pi Zero MAC prefix (02:fb:*)
    for iface in /sys/class/net/usb*; do
        if [[ -f "$iface/address" ]]; then
            mac=$(cat "$iface/address")
            if [[ "$mac" == 02:fb:* ]]; then
                basename "$iface"
                return 0
            fi
        fi
    done

    # Fallback to usb0
    if ip link show usb0 &>/dev/null; then
        echo "usb0"
        return 0
    fi

    return 1
}

HOST_IP="10.55.0.1"
NETMASK="24"
PEER_IP="10.55.0.2"
LOG_TAG="secubox-eye-network"

log() {
    logger -t "$LOG_TAG" "$*"
    echo "$*"
}

case "${1:-}" in
    up)
        IFACE=$(find_interface)
        if [[ -z "$IFACE" ]]; then
            log "ERROR: No Eye Remote interface found"
            exit 1
        fi

        log "Configuring $IFACE (Host: $HOST_IP/$NETMASK)"

        # CRITICAL: Disable reverse path filter to prevent martian source drops
        sysctl -w net.ipv4.conf.$IFACE.rp_filter=0 2>/dev/null || true
        sysctl -w net.ipv4.conf.all.rp_filter=0 2>/dev/null || true

        # Wait for interface to be ready
        for i in {1..20}; do
            if ip link show "$IFACE" &>/dev/null; then
                break
            fi
            sleep 0.5
        done

        # Bring interface up
        ip link set "$IFACE" up 2>/dev/null || true

        # Check if already configured
        if ip addr show "$IFACE" | grep -q "$HOST_IP"; then
            log "Interface $IFACE already configured"
        else
            # Remove any existing IPs and add ours
            ip addr flush dev "$IFACE" 2>/dev/null || true
            ip addr add "$HOST_IP/$NETMASK" dev "$IFACE" 2>/dev/null || true
        fi

        # Wait for link to be up
        sleep 1

        log "Interface $IFACE UP, peer at $PEER_IP"

        # Notify SecuBox API (run in background)
        (
            sleep 2
            curl -s --unix-socket /run/secubox/eye-remote.sock \
                -X POST "http://localhost/api/v1/eye-remote/connected?peer_ip=$PEER_IP" \
                2>/dev/null || true
        ) &
        ;;

    down)
        IFACE=$(find_interface)
        if [[ -z "$IFACE" ]]; then
            log "No interface to remove"
            exit 0
        fi

        log "Removing $IFACE configuration"
        ip addr del "$HOST_IP/$NETMASK" dev "$IFACE" 2>/dev/null || true

        # Notify SecuBox API
        curl -s --unix-socket /run/secubox/eye-remote.sock \
            -X POST "http://localhost/api/v1/eye-remote/disconnected" \
            2>/dev/null || true
        ;;

    status)
        IFACE=$(find_interface)
        if [[ -z "$IFACE" ]]; then
            echo "No Eye Remote interface found"
            exit 1
        fi
        ip addr show "$IFACE"
        echo "rp_filter: $(cat /proc/sys/net/ipv4/conf/$IFACE/rp_filter 2>/dev/null || echo 'N/A')"
        ping -c 1 -W 2 "$PEER_IP" &>/dev/null && echo "Peer $PEER_IP: REACHABLE" || echo "Peer $PEER_IP: NOT REACHABLE"
        ;;

    *)
        echo "Usage: $0 up|down|status"
        exit 1
        ;;
esac
