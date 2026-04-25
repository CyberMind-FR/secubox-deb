#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# SecuBox-Deb :: gadget-setup.sh
# CyberMind — Gérald Kerma
#
# USB Gadget configuration for SecuBox Eye Remote (ECM + ACM)
# Simple, minimal, working version
#
# Usage: gadget-setup.sh {up|down|status}
#
# License: Proprietary / ANSSI CSPN candidate
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

readonly VERSION="2.2.0"
readonly GADGET="/sys/kernel/config/usb_gadget/secubox"

log() { echo "[eye-gadget] $*"; logger -t eye-gadget "$*"; }

# ═══════════════════════════════════════════════════════════════════════════════
# Tear down existing gadget
# ═══════════════════════════════════════════════════════════════════════════════

gadget_down() {
    [[ -d "$GADGET" ]] || return 0

    log "Stopping gadget..."
    echo "" > "$GADGET/UDC" 2>/dev/null || true

    # Remove symlinks and directories in reverse order
    rm -f $GADGET/configs/c.1/*.usb0 2>/dev/null || true
    rmdir $GADGET/configs/c.1/strings/0x409 2>/dev/null || true
    rmdir $GADGET/configs/c.1/strings 2>/dev/null || true
    rmdir $GADGET/configs/c.1 2>/dev/null || true
    rmdir $GADGET/configs 2>/dev/null || true
    rmdir $GADGET/functions/ecm.usb0 2>/dev/null || true
    rmdir $GADGET/functions/acm.usb0 2>/dev/null || true
    rmdir $GADGET/functions 2>/dev/null || true
    rmdir $GADGET/strings/0x409 2>/dev/null || true
    rmdir $GADGET/strings 2>/dev/null || true
    rmdir $GADGET 2>/dev/null || true

    log "Gadget stopped"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Create and start USB gadget
# ═══════════════════════════════════════════════════════════════════════════════

gadget_up() {
    log "Starting USB gadget v${VERSION}..."

    # Clean up any existing gadget
    gadget_down

    # Create gadget directory and enter it
    mkdir -p "$GADGET" && cd "$GADGET"

    # USB IDs (Linux Foundation Multifunction Composite Gadget)
    echo 0x1d6b > idVendor
    echo 0x0104 > idProduct
    echo 0x0200 > bcdDevice

    # USB class: Miscellaneous (for composite device)
    echo 0xEF > bDeviceClass
    echo 0x02 > bDeviceSubClass
    echo 0x01 > bDeviceProtocol

    # Strings (0x409 = US English)
    mkdir -p strings/0x409
    echo "CyberMind SecuBox" > strings/0x409/manufacturer
    echo "Eye Remote" > strings/0x409/product
    SERIAL=$(grep -oP 'Serial\s*:\s*\K[0-9a-f]+' /proc/cpuinfo 2>/dev/null || echo "0000001")
    echo "$SERIAL" > strings/0x409/serialnumber

    # Function 1: CDC-ECM (Ethernet for Linux/macOS)
    mkdir -p functions/ecm.usb0
    echo "02:00:00:00:00:01" > functions/ecm.usb0/host_addr
    echo "02:00:00:00:00:02" > functions/ecm.usb0/dev_addr

    # Function 2: CDC-ACM (Serial console)
    mkdir -p functions/acm.usb0

    # Configuration
    mkdir -p configs/c.1/strings/0x409
    echo "SecuBox Eye Remote (ECM + ACM)" > configs/c.1/strings/0x409/configuration
    echo 500 > configs/c.1/MaxPower

    # Link functions to configuration (paths relative to gadget root)
    ln -sf functions/ecm.usb0 configs/c.1/
    ln -sf functions/acm.usb0 configs/c.1/

    # Bind to UDC
    UDC=$(ls /sys/class/udc/ | head -1)
    if [[ -z "$UDC" ]]; then
        log "ERROR: No UDC found"
        return 1
    fi
    echo "$UDC" > UDC

    log "Gadget started on $UDC"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Status
# ═══════════════════════════════════════════════════════════════════════════════

gadget_status() {
    if [[ -d "$GADGET" ]]; then
        local udc
        udc=$(cat "$GADGET/UDC" 2>/dev/null)
        if [[ -n "$udc" ]]; then
            echo '{"status":"running","udc":"'"$udc"'","version":"'"$VERSION"'"}'
        else
            echo '{"status":"configured","udc":null,"version":"'"$VERSION"'"}'
        fi
    else
        echo '{"status":"stopped","udc":null,"version":"'"$VERSION"'"}'
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════

case "${1:-}" in
    up|start)   gadget_up ;;
    down|stop)  gadget_down ;;
    status)     gadget_status ;;
    *)          echo "Usage: $0 {up|down|status}"; exit 1 ;;
esac
