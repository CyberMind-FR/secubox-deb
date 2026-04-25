#!/bin/bash
# SecuBox Eye Remote - Host-side USB OTG network setup
# Called by udev when Pi Zero gadget is connected

IFACE="${1:-enx020000000001}"
HOST_IP="10.55.0.1/30"
LOG="/var/log/secubox-otg.log"

echo "$(date): Configuring $IFACE with $HOST_IP" >> "$LOG"

# Wait for interface to be ready
sleep 1

# Configure IP (ignore if already set)
ip addr add "$HOST_IP" dev "$IFACE" 2>/dev/null || true
ip link set "$IFACE" up

echo "$(date): $IFACE configured" >> "$LOG"
