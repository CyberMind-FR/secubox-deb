#!/usr/bin/env bash
# SecuBox-Deb :: qemu-screenshot.sh
# CyberMind — Gérald Kerma
# Boot SecuBox in QEMU with screenshot capability
set -euo pipefail

readonly MODULE="qemu-screenshot"
readonly VERSION="1.0.0"

IMAGE="${1:-/home/reepost/secubox-live-v4.img}"
SCREENSHOT_DIR="${2:-$(dirname "$0")/../docs/screenshots}"
MONITOR_SOCKET="/tmp/qemu-secubox-monitor.sock"

mkdir -p "$SCREENSHOT_DIR"

echo "=== SecuBox QEMU Screenshot Tool ==="
echo "Image: $IMAGE"
echo "Screenshots: $SCREENSHOT_DIR"
echo ""
echo "Controls:"
echo "  - QEMU monitor on socket: $MONITOR_SOCKET"
echo "  - Take screenshot: echo 'screendump $SCREENSHOT_DIR/screenshot.ppm' | socat - UNIX-CONNECT:$MONITOR_SOCKET"
echo "  - Or use: ./qemu-screenshot.sh snap <name>"
echo ""

if [[ "${1:-}" == "snap" ]]; then
    # Take a screenshot
    NAME="${2:-$(date +%Y%m%d-%H%M%S)}"
    OUTPUT="$SCREENSHOT_DIR/${NAME}.ppm"
    echo "screendump $OUTPUT" | socat - UNIX-CONNECT:"$MONITOR_SOCKET"
    echo "Screenshot saved: $OUTPUT"

    # Convert to PNG if ImageMagick available
    if command -v convert &>/dev/null; then
        convert "$OUTPUT" "${OUTPUT%.ppm}.png"
        rm "$OUTPUT"
        echo "Converted to: ${OUTPUT%.ppm}.png"
    fi
    exit 0
fi

# Boot QEMU with monitor socket
qemu-system-x86_64 \
    -enable-kvm \
    -m 2048 \
    -cpu host \
    -smp 2 \
    -drive file="$IMAGE",format=raw,if=virtio \
    -device virtio-net-pci,netdev=net0 \
    -netdev user,id=net0,hostfwd=tcp::9443-:443,hostfwd=tcp::9080-:80 \
    -display gtk \
    -vga virtio \
    -monitor unix:"$MONITOR_SOCKET",server,nowait \
    -name "SecuBox Live"
