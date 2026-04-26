#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# SecuBox-Deb :: gadget-setup.sh
# CyberMind — Gérald Kerma
#
# USB Gadget configuration for SecuBox Eye Remote (ECM + ACM + Mass Storage)
# Composite USB device with network, serial, and storage functions
#
# Usage: gadget-setup.sh {up|down|status}
#
# License: Proprietary / ANSSI CSPN candidate
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

readonly VERSION="2.4.0"
readonly GADGET="/sys/kernel/config/usb_gadget/secubox"

# Mass storage configuration
readonly STORAGE_IMAGE="/var/lib/secubox/eye-remote/storage.img"
readonly STORAGE_SIZE_MB=2048  # Size in MB for the storage image (2GB for live images)
readonly STORAGE_ENABLED=true  # Set to false to disable mass storage

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
    rm -f $GADGET/configs/c.1/mass_storage.usb0 2>/dev/null || true
    rmdir $GADGET/configs/c.1/strings/0x409 2>/dev/null || true
    rmdir $GADGET/configs/c.1/strings 2>/dev/null || true
    rmdir $GADGET/configs/c.1 2>/dev/null || true
    rmdir $GADGET/configs 2>/dev/null || true
    rmdir $GADGET/functions/ecm.usb0 2>/dev/null || true
    rmdir $GADGET/functions/acm.usb0 2>/dev/null || true
    rmdir $GADGET/functions/mass_storage.usb0/lun.0 2>/dev/null || true
    rmdir $GADGET/functions/mass_storage.usb0 2>/dev/null || true
    rmdir $GADGET/functions 2>/dev/null || true
    rmdir $GADGET/strings/0x409 2>/dev/null || true
    rmdir $GADGET/strings 2>/dev/null || true
    rmdir $GADGET 2>/dev/null || true

    log "Gadget stopped"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Create storage image if needed
# ═══════════════════════════════════════════════════════════════════════════════

create_storage_image() {
    if [[ -f "$STORAGE_IMAGE" ]]; then
        log "Storage image exists: $STORAGE_IMAGE"
        return 0
    fi

    log "Creating storage image: $STORAGE_IMAGE (${STORAGE_SIZE_MB}MB)..."
    mkdir -p "$(dirname "$STORAGE_IMAGE")"

    # Create sparse file
    dd if=/dev/zero of="$STORAGE_IMAGE" bs=1M count=0 seek="$STORAGE_SIZE_MB" 2>/dev/null

    # Format as FAT32
    mkfs.vfat -F 32 -n "SECUBOX" "$STORAGE_IMAGE" >/dev/null 2>&1 || {
        log "WARNING: mkfs.vfat failed, storage will be unformatted"
    }

    log "Storage image created"
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

    # Function 3: Mass Storage (optional)
    if [[ "$STORAGE_ENABLED" == "true" ]]; then
        create_storage_image
        mkdir -p functions/mass_storage.usb0/lun.0
        echo 1 > functions/mass_storage.usb0/lun.0/removable
        echo 0 > functions/mass_storage.usb0/lun.0/cdrom
        echo 0 > functions/mass_storage.usb0/lun.0/ro
        echo 0 > functions/mass_storage.usb0/lun.0/nofua
        echo "$STORAGE_IMAGE" > functions/mass_storage.usb0/lun.0/file
        log "Mass storage enabled: $STORAGE_IMAGE"
    fi

    # Configuration
    mkdir -p configs/c.1/strings/0x409
    if [[ "$STORAGE_ENABLED" == "true" ]]; then
        echo "SecuBox Eye Remote (ECM + ACM + Storage)" > configs/c.1/strings/0x409/configuration
    else
        echo "SecuBox Eye Remote (ECM + ACM)" > configs/c.1/strings/0x409/configuration
    fi
    echo 500 > configs/c.1/MaxPower

    # Link functions to configuration (paths relative to gadget root)
    ln -sf functions/ecm.usb0 configs/c.1/
    ln -sf functions/acm.usb0 configs/c.1/
    if [[ "$STORAGE_ENABLED" == "true" ]]; then
        ln -sf functions/mass_storage.usb0 configs/c.1/
    fi

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
        local udc storage_status
        udc=$(cat "$GADGET/UDC" 2>/dev/null)
        if [[ -f "$STORAGE_IMAGE" ]]; then
            storage_status="enabled"
        else
            storage_status="disabled"
        fi
        if [[ -n "$udc" ]]; then
            echo '{"status":"running","udc":"'"$udc"'","version":"'"$VERSION"'","storage":"'"$storage_status"'"}'
        else
            echo '{"status":"configured","udc":null,"version":"'"$VERSION"'","storage":"'"$storage_status"'"}'
        fi
    else
        echo '{"status":"stopped","udc":null,"version":"'"$VERSION"'","storage":"disabled"}'
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Storage-only gadget (for U-Boot compatibility)
# U-Boot has limited support for composite gadgets - this mode exposes
# only mass storage for reliable detection from U-Boot USB commands
# ═══════════════════════════════════════════════════════════════════════════════

gadget_storage_only() {
    log "Starting USB gadget v${VERSION} (STORAGE-ONLY mode for U-Boot)..."

    # Clean up any existing gadget
    gadget_down

    # Create storage image if needed
    create_storage_image

    # Create gadget directory and enter it
    mkdir -p "$GADGET" && cd "$GADGET"

    # USB IDs - Use standard mass storage class for maximum compatibility
    echo 0x1d6b > idVendor      # Linux Foundation
    echo 0x0100 > idProduct     # Mass Storage (not composite)
    echo 0x0200 > bcdDevice

    # USB class: Defined at interface level for single-function device
    echo 0x00 > bDeviceClass
    echo 0x00 > bDeviceSubClass
    echo 0x00 > bDeviceProtocol

    # Strings (0x409 = US English)
    mkdir -p strings/0x409
    echo "CyberMind SecuBox" > strings/0x409/manufacturer
    echo "Eye Remote Boot Media" > strings/0x409/product
    SERIAL=$(grep -oP 'Serial\s*:\s*\K[0-9a-f]+' /proc/cpuinfo 2>/dev/null || echo "0000001")
    echo "$SERIAL" > strings/0x409/serialnumber

    # Function: Mass Storage ONLY
    mkdir -p functions/mass_storage.usb0/lun.0
    echo 1 > functions/mass_storage.usb0/lun.0/removable
    echo 0 > functions/mass_storage.usb0/lun.0/cdrom
    echo 0 > functions/mass_storage.usb0/lun.0/ro
    echo 0 > functions/mass_storage.usb0/lun.0/nofua
    echo "$STORAGE_IMAGE" > functions/mass_storage.usb0/lun.0/file

    # Configuration
    mkdir -p configs/c.1/strings/0x409
    echo "SecuBox Eye Remote Boot Media" > configs/c.1/strings/0x409/configuration
    echo 200 > configs/c.1/MaxPower

    # Link function to configuration
    ln -sf functions/mass_storage.usb0 configs/c.1/

    # Bind to UDC
    UDC=$(ls /sys/class/udc/ | head -1)
    if [[ -z "$UDC" ]]; then
        log "ERROR: No UDC found"
        return 1
    fi
    echo "$UDC" > UDC

    log "Storage-only gadget started on $UDC"
    log "U-Boot should now see: 1 Storage Device(s) found"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════

case "${1:-}" in
    up|start)        gadget_up ;;
    down|stop)       gadget_down ;;
    status)          gadget_status ;;
    storage|uboot)   gadget_storage_only ;;
    *)
        echo "Usage: $0 {up|down|status|storage}"
        echo ""
        echo "Commands:"
        echo "  up|start   - Start composite gadget (ECM + ACM + Storage)"
        echo "  down|stop  - Stop gadget"
        echo "  status     - Show gadget status"
        echo "  storage    - Start storage-only gadget (for U-Boot compatibility)"
        echo ""
        echo "Note: U-Boot has limited support for composite USB gadgets."
        echo "Use 'storage' mode when flashing from U-Boot, then switch to 'up'"
        echo "for normal operation with network and serial console."
        exit 1
        ;;
esac
