#!/bin/bash
# SecuBox Eye Remote - Host-side USB OTG network setup
# Called by udev when Pi Zero gadget is connected

HOST_IP="10.55.0.1/30"
TARGET_MAC="02:00:00:00:00:01"
LOG="/var/log/secubox-otg.log"

# Find interface by MAC (handles renaming)
IFACE=$(ip -o link show | grep "$TARGET_MAC" | awk -F': ' '{print $2}')

if [[ -z "$IFACE" ]]; then
    echo "$(date): No interface with MAC $TARGET_MAC found" >> "$LOG"
    exit 1
fi

echo "$(date): Configuring $IFACE with $HOST_IP" >> "$LOG"

# Wait for interface to be ready
sleep 1

# Configure IP
ip addr add "$HOST_IP" dev "$IFACE" 2>/dev/null || true
ip link set "$IFACE" up

echo "$(date): $IFACE configured" >> "$LOG"
