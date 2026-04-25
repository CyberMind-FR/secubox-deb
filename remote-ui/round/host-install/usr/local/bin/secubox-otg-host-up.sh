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

# Enable NAT for Pi internet access
sysctl -w net.ipv4.ip_forward=1 >> "$LOG" 2>&1
# Find default route interface and add masquerade
DEFAULT_IFACE=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'dev \K\S+')
if [[ -n "$DEFAULT_IFACE" ]]; then
    iptables -t nat -C POSTROUTING -s 10.55.0.0/30 -o "$DEFAULT_IFACE" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s 10.55.0.0/30 -o "$DEFAULT_IFACE" -j MASQUERADE
    echo "$(date): NAT enabled via $DEFAULT_IFACE" >> "$LOG"
fi

echo "$(date): $IFACE configured" >> "$LOG"
