#!/usr/bin/env bash
# SecuBox-Deb :: capture-module-screenshots.sh
# CyberMind — Gérald Kerma
# Interactive screenshot capture for SecuBox modules
set -euo pipefail

readonly MODULE="capture-screenshots"
readonly VERSION="1.0.0"

SCREENSHOT_DIR="${1:-$(dirname "$0")/../docs/screenshots}"
MONITOR_SOCKET="/tmp/qemu-secubox-monitor.sock"

mkdir -p "$SCREENSHOT_DIR"

# List of modules to capture
MODULES=(
    "login"
    "dashboard"
    "crowdsec"
    "netdata"
    "wireguard"
    "dpi"
    "netmodes"
    "qos"
    "mediaflow"
    "vhost"
    "system"
)

snap() {
    local name="$1"
    local output="$SCREENSHOT_DIR/${name}.ppm"

    if [[ ! -S "$MONITOR_SOCKET" ]]; then
        echo "ERROR: QEMU not running. Start with: ./qemu-screenshot.sh"
        exit 1
    fi

    echo "screendump $output" | socat - UNIX-CONNECT:"$MONITOR_SOCKET"

    # Convert to PNG
    if command -v convert &>/dev/null; then
        convert "$output" "${output%.ppm}.png"
        rm "$output"
        echo "✓ Captured: ${name}.png"
    else
        echo "✓ Captured: ${name}.ppm"
    fi
}

echo "=== SecuBox Module Screenshot Capture ==="
echo ""
echo "Prerequisites:"
echo "  1. Start QEMU: ./qemu-screenshot.sh"
echo "  2. Login to SecuBox (root/secubox)"
echo "  3. Navigate to each module, then press Enter here"
echo ""

for module in "${MODULES[@]}"; do
    read -rp "Navigate to $module, then press Enter to capture... "
    snap "secubox-$module"
done

echo ""
echo "=== All screenshots captured ==="
ls -la "$SCREENSHOT_DIR"/secubox-*.png 2>/dev/null || ls -la "$SCREENSHOT_DIR"/secubox-*.ppm
