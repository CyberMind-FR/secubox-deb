#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# SecuBox-Deb :: usb-network-up.sh
# CyberMind — Gérald Kerma
#
# Configure USB OTG network interface after gadget starts
# Supports both usb0 and usb1 interfaces (ECM creates usb1 on some kernels)
# ═══════════════════════════════════════════════════════════════════════════════

LOG=/var/log/usb-network.log
exec >> "$LOG" 2>&1
echo "=== usb-network-up.sh $(date) ==="

# Wait for interface to appear
IFACE=""
for i in {1..30}; do
    if ip link show usb0 &>/dev/null; then
        IFACE="usb0"
        break
    elif ip link show usb1 &>/dev/null; then
        IFACE="usb1"
        break
    fi
    sleep 0.5
done

if [ -z "${IFACE:-}" ]; then
    echo "WARNING: No USB interface found after 15s"
    exit 0
fi

echo "Configuring $IFACE..."
ip addr flush dev "$IFACE" 2>/dev/null || true
ip addr add 10.55.0.2/30 dev "$IFACE"
ip link set "$IFACE" up
ip route add default via 10.55.0.1 dev "$IFACE" 2>/dev/null || true

echo "Done: $(ip addr show $IFACE | grep inet)"
logger -t "secubox-eye-remote" "USB network configured: $IFACE = 10.55.0.2/30"
