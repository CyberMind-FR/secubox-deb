#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# SecuBox Eye Remote :: fix-rfkill-boot.sh
# CyberMind — Gérald Kerma
#
# Fix rfkill boot hang on Raspberry Pi Zero W
# Disables WiFi/Bluetooth to prevent rfkill service hang
#
# Run this script on the Pi (via serial console or SD card mount)
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

echo "=== SecuBox Eye Remote - Fix rfkill boot hang ==="

# 1. Disable WiFi and Bluetooth in config.txt
CONFIG="/boot/firmware/config.txt"
if [[ -f "$CONFIG" ]]; then
    # Add dtoverlay to disable WiFi and Bluetooth if not already present
    if ! grep -q "dtoverlay=disable-wifi" "$CONFIG"; then
        echo "" >> "$CONFIG"
        echo "# Disable WiFi to prevent rfkill boot hang (OTG mode)" >> "$CONFIG"
        echo "dtoverlay=disable-wifi" >> "$CONFIG"
        echo "Added: dtoverlay=disable-wifi"
    fi

    if ! grep -q "dtoverlay=disable-bt" "$CONFIG"; then
        echo "# Disable Bluetooth to prevent rfkill boot hang" >> "$CONFIG"
        echo "dtoverlay=disable-bt" >> "$CONFIG"
        echo "Added: dtoverlay=disable-bt"
    fi
else
    echo "WARNING: $CONFIG not found, trying /boot/config.txt"
    CONFIG="/boot/config.txt"
    if [[ -f "$CONFIG" ]]; then
        if ! grep -q "dtoverlay=disable-wifi" "$CONFIG"; then
            echo "" >> "$CONFIG"
            echo "dtoverlay=disable-wifi" >> "$CONFIG"
            echo "dtoverlay=disable-bt" >> "$CONFIG"
            echo "Added WiFi/BT disable overlays"
        fi
    fi
fi

# 2. Mask systemd-rfkill to prevent it from hanging
systemctl mask systemd-rfkill.service 2>/dev/null || true
systemctl mask systemd-rfkill.socket 2>/dev/null || true
echo "Masked systemd-rfkill service"

# 3. Disable wpa_supplicant since we're using OTG only
systemctl disable wpa_supplicant 2>/dev/null || true
systemctl stop wpa_supplicant 2>/dev/null || true
echo "Disabled wpa_supplicant"

# 4. Disable hciuart (Bluetooth UART)
systemctl disable hciuart 2>/dev/null || true
systemctl stop hciuart 2>/dev/null || true
echo "Disabled hciuart"

# 5. Blacklist WiFi/BT kernel modules
BLACKLIST="/etc/modprobe.d/secubox-disable-wireless.conf"
cat > "$BLACKLIST" << 'EOF'
# SecuBox Eye Remote - Disable wireless to prevent rfkill hang
blacklist brcmfmac
blacklist brcmutil
blacklist btbcm
blacklist hci_uart
EOF
echo "Created module blacklist: $BLACKLIST"

# 6. Unblock rfkill now (if system is running)
rfkill unblock all 2>/dev/null || true

echo ""
echo "=== Fix applied ==="
echo "Reboot required for changes to take effect"
echo "Run: sudo reboot"
