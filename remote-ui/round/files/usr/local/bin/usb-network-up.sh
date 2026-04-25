#!/bin/bash
# SecuBox Eye Remote - USB Network Configuration
# Configures IP on USB gadget interface after gadget starts

LOG=/var/log/usb-network.log
exec >> "$LOG" 2>&1
echo "=== usb-network-up.sh $(date) ==="

# Wait for interface to appear (up to 30 seconds)
IFACE=""
for i in {1..60}; do
    for dev in usb0 usb1; do
        if ip link show "$dev" &>/dev/null; then
            IFACE="$dev"
            break 2
        fi
    done
    sleep 0.5
done

if [[ -z "$IFACE" ]]; then
    echo "ERROR: No USB interface found after 30s"
    exit 1
fi

echo "Found interface: $IFACE"

# Configure IP
ip addr flush dev "$IFACE" 2>/dev/null || true
ip addr add 10.55.0.2/30 dev "$IFACE" || { echo "ERROR: Failed to add IP"; exit 1; }
ip link set "$IFACE" up

# Add route (optional, may fail if already exists)
ip route add default via 10.55.0.1 dev "$IFACE" 2>/dev/null || true

echo "Configured: $IFACE = 10.55.0.2/30"
ip addr show "$IFACE" | grep inet
logger -t "eye-remote" "USB network: $IFACE = 10.55.0.2/30"
