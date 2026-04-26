#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# SecuBox Eye Remote :: fix-rfkill-sdcard.sh
# CyberMind — Gérald Kerma
#
# Fix rfkill boot hang by editing SD card directly
# Run this from host with Pi's SD card mounted
#
# Usage: ./fix-rfkill-sdcard.sh /media/user/bootfs /media/user/rootfs
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

BOOT="${1:-/media/$USER/bootfs}"
ROOT="${2:-/media/$USER/rootfs}"

echo "=== SecuBox Eye Remote - Fix rfkill (SD card) ==="
echo "Boot partition: $BOOT"
echo "Root partition: $ROOT"

# Check partitions exist
if [[ ! -d "$BOOT" ]]; then
    echo "ERROR: Boot partition not found at $BOOT"
    echo "Mount the SD card and provide the correct path"
    exit 1
fi

if [[ ! -d "$ROOT" ]]; then
    echo "ERROR: Root partition not found at $ROOT"
    exit 1
fi

# 1. Fix config.txt on boot partition
CONFIG=""
for f in "$BOOT/config.txt" "$BOOT/firmware/config.txt"; do
    if [[ -f "$f" ]]; then
        CONFIG="$f"
        break
    fi
done

if [[ -n "$CONFIG" ]]; then
    echo "Found config: $CONFIG"

    if ! grep -q "dtoverlay=disable-wifi" "$CONFIG"; then
        echo "" >> "$CONFIG"
        echo "# SecuBox Eye Remote - Disable WiFi/BT for OTG mode" >> "$CONFIG"
        echo "dtoverlay=disable-wifi" >> "$CONFIG"
        echo "dtoverlay=disable-bt" >> "$CONFIG"
        echo "✓ Added WiFi/BT disable overlays to config.txt"
    else
        echo "✓ WiFi/BT already disabled in config.txt"
    fi
else
    echo "WARNING: config.txt not found"
fi

# 2. Blacklist wireless modules
BLACKLIST="$ROOT/etc/modprobe.d/secubox-disable-wireless.conf"
mkdir -p "$(dirname "$BLACKLIST")"
cat > "$BLACKLIST" << 'EOF'
# SecuBox Eye Remote - Disable wireless to prevent rfkill hang
blacklist brcmfmac
blacklist brcmutil
blacklist btbcm
blacklist hci_uart
EOF
echo "✓ Created module blacklist"

# 3. Mask rfkill service
RFKILL_MASK="$ROOT/etc/systemd/system/systemd-rfkill.service"
ln -sf /dev/null "$RFKILL_MASK" 2>/dev/null || true
ln -sf /dev/null "$ROOT/etc/systemd/system/systemd-rfkill.socket" 2>/dev/null || true
echo "✓ Masked systemd-rfkill"

# 4. Disable wpa_supplicant
rm -f "$ROOT/etc/systemd/system/multi-user.target.wants/wpa_supplicant.service" 2>/dev/null || true
echo "✓ Disabled wpa_supplicant"

# 5. Disable hciuart
rm -f "$ROOT/etc/systemd/system/multi-user.target.wants/hciuart.service" 2>/dev/null || true
echo "✓ Disabled hciuart"

echo ""
echo "=== Fix applied to SD card ==="
echo "Unmount SD card and boot the Pi"
echo ""
echo "Commands:"
echo "  sync"
echo "  sudo umount $BOOT"
echo "  sudo umount $ROOT"
