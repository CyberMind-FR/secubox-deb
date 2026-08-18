#!/bin/bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

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

readonly VERSION="2.5.1"
readonly GADGET="/sys/kernel/config/usb_gadget/secubox"

# Mass storage configuration
readonly STORAGE_IMAGE="/var/lib/secubox/eye-remote/storage.img"
readonly STORAGE_SIZE_MB=2048  # Size in MB for the storage image (2GB for live images)
readonly STORAGE_ENABLED=true  # Set to false to disable mass storage

# Mode switch safeguards
readonly LOCK_FILE="/run/secubox/gadget-switch.lock"
readonly SWITCH_DELAY=2  # Seconds to wait between down and up
readonly LOCK_TIMEOUT=30 # Seconds before lock expires (stale lock cleanup)

# HID keyboard report descriptor (boot protocol keyboard - 8 bytes)
# Format: modifier, reserved, key1-key6
HID_KEYBOARD_REPORT_DESC() {
    echo -ne '\x05\x01'      # Usage Page (Generic Desktop)
    echo -ne '\x09\x06'      # Usage (Keyboard)
    echo -ne '\xa1\x01'      # Collection (Application)
    echo -ne '\x05\x07'      #   Usage Page (Key Codes)
    echo -ne '\x19\xe0'      #   Usage Minimum (224) - Left Control
    echo -ne '\x29\xe7'      #   Usage Maximum (231) - Right GUI
    echo -ne '\x15\x00'      #   Logical Minimum (0)
    echo -ne '\x25\x01'      #   Logical Maximum (1)
    echo -ne '\x75\x01'      #   Report Size (1)
    echo -ne '\x95\x08'      #   Report Count (8)
    echo -ne '\x81\x02'      #   Input (Data, Variable, Absolute) - Modifier byte
    echo -ne '\x95\x01'      #   Report Count (1)
    echo -ne '\x75\x08'      #   Report Size (8)
    echo -ne '\x81\x01'      #   Input (Constant) - Reserved byte
    echo -ne '\x95\x06'      #   Report Count (6)
    echo -ne '\x75\x08'      #   Report Size (8)
    echo -ne '\x15\x00'      #   Logical Minimum (0)
    echo -ne '\x25\x65'      #   Logical Maximum (101)
    echo -ne '\x05\x07'      #   Usage Page (Key Codes)
    echo -ne '\x19\x00'      #   Usage Minimum (0)
    echo -ne '\x29\x65'      #   Usage Maximum (101)
    echo -ne '\x81\x00'      #   Input (Data, Array) - Key array
    echo -ne '\xc0'          # End Collection
}

log() { echo "[eye-gadget] $*"; logger -t eye-gadget "$*"; }

# ═══════════════════════════════════════════════════════════════════════════════
# Mode Switch Safeguards (prevent crash from rapid switches)
# ═══════════════════════════════════════════════════════════════════════════════

acquire_lock() {
    mkdir -p "$(dirname "$LOCK_FILE")"

    # Clean up stale lock (older than LOCK_TIMEOUT)
    if [[ -f "$LOCK_FILE" ]]; then
        local lock_age=$(( $(date +%s) - $(stat -c %Y "$LOCK_FILE" 2>/dev/null || echo 0) ))
        if (( lock_age > LOCK_TIMEOUT )); then
            log "Removing stale lock (age: ${lock_age}s)"
            rm -f "$LOCK_FILE"
        fi
    fi

    # Try to acquire lock
    if [[ -f "$LOCK_FILE" ]]; then
        local lock_pid=$(cat "$LOCK_FILE" 2>/dev/null)
        if [[ -n "$lock_pid" ]] && kill -0 "$lock_pid" 2>/dev/null; then
            log "Mode switch in progress (PID $lock_pid), waiting..."
            # Wait up to 10 seconds for existing switch to complete
            for i in {1..20}; do
                sleep 0.5
                [[ ! -f "$LOCK_FILE" ]] && break
            done
        fi
    fi

    # Acquire lock
    echo $$ > "$LOCK_FILE"
    trap 'rm -f "$LOCK_FILE"' EXIT
    log "Lock acquired (PID $$)"
}

release_lock() {
    rm -f "$LOCK_FILE"
    trap - EXIT
}

safe_mode_switch() {
    local target_mode="$1"

    acquire_lock

    # Stop existing gadget with delay
    gadget_down

    # Critical: Wait for USB host to detect disconnection
    log "Waiting ${SWITCH_DELAY}s for USB bus to settle..."
    sleep "$SWITCH_DELAY"

    # Start new mode
    case "$target_mode" in
        up|start|composite) gadget_up ;;
        network|ecm)        gadget_network ;;
        hid|keyboard)       gadget_hid ;;
        storage|uboot)      gadget_storage_only ;;
        silent|silent-storage) gadget_silent_storage ;;
        *)                  log "Unknown mode: $target_mode"; return 1 ;;
    esac

    release_lock
}

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
    rm -f $GADGET/configs/c.1/hid.usb0 2>/dev/null || true
    rmdir $GADGET/configs/c.1/strings/0x409 2>/dev/null || true
    rmdir $GADGET/configs/c.1/strings 2>/dev/null || true
    rmdir $GADGET/configs/c.1 2>/dev/null || true
    rmdir $GADGET/configs 2>/dev/null || true
    rmdir $GADGET/functions/ecm.usb0 2>/dev/null || true
    rmdir $GADGET/functions/acm.usb0 2>/dev/null || true
    rmdir $GADGET/functions/hid.usb0 2>/dev/null || true
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
# HID Keyboard gadget with ACM serial (fallback when host doesn't support network)
# Useful for typing commands into U-Boot console or hosts without CDC-ECM support
# ═══════════════════════════════════════════════════════════════════════════════

gadget_hid() {
    log "Starting USB gadget v${VERSION} (HID KEYBOARD mode)..."

    # Clean up any existing gadget
    gadget_down

    # Load HID module if needed
    modprobe usb_f_hid 2>/dev/null || true

    # Create gadget directory and enter it
    mkdir -p "$GADGET" && cd "$GADGET"

    # USB IDs - Use composite gadget class for HID + ACM
    echo 0x1d6b > idVendor      # Linux Foundation
    echo 0x0104 > idProduct     # Multifunction Composite Gadget
    echo 0x0200 > bcdDevice

    # USB class: Defined at interface level
    echo 0x00 > bDeviceClass
    echo 0x00 > bDeviceSubClass
    echo 0x00 > bDeviceProtocol

    # Strings (0x409 = US English)
    mkdir -p strings/0x409
    echo "CyberMind SecuBox" > strings/0x409/manufacturer
    echo "Eye Remote Keyboard" > strings/0x409/product
    SERIAL=$(grep -oP 'Serial\s*:\s*\K[0-9a-f]+' /proc/cpuinfo 2>/dev/null || echo "0000001")
    echo "$SERIAL" > strings/0x409/serialnumber

    # Function 1: HID Keyboard
    mkdir -p functions/hid.usb0
    echo 1 > functions/hid.usb0/protocol      # Keyboard protocol
    echo 1 > functions/hid.usb0/subclass      # Boot interface subclass
    echo 8 > functions/hid.usb0/report_length # 8 bytes per report
    HID_KEYBOARD_REPORT_DESC > functions/hid.usb0/report_desc

    # Function 2: CDC-ACM (Serial console) - always useful for debugging
    mkdir -p functions/acm.usb0

    # Configuration
    mkdir -p configs/c.1/strings/0x409
    echo "SecuBox Eye Remote (HID Keyboard + ACM)" > configs/c.1/strings/0x409/configuration
    echo 100 > configs/c.1/MaxPower

    # Link functions to configuration
    ln -sf functions/hid.usb0 configs/c.1/
    ln -sf functions/acm.usb0 configs/c.1/

    # Bind to UDC
    UDC=$(ls /sys/class/udc/ | head -1)
    if [[ -z "$UDC" ]]; then
        log "ERROR: No UDC found"
        return 1
    fi
    echo "$UDC" > UDC

    log "HID gadget started on $UDC"
    log "Keyboard device: /dev/hidg0"
    log "Serial console: /dev/ttyGS0"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Network gadget (ECM + ACM only, no storage)
# For when we want network without mass storage overhead
# ═══════════════════════════════════════════════════════════════════════════════

gadget_network() {
    log "Starting USB gadget v${VERSION} (NETWORK mode)..."

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

    # Link functions to configuration
    ln -sf functions/ecm.usb0 configs/c.1/
    ln -sf functions/acm.usb0 configs/c.1/

    # Bind to UDC
    UDC=$(ls /sys/class/udc/ | head -1)
    if [[ -z "$UDC" ]]; then
        log "ERROR: No UDC found"
        return 1
    fi
    echo "$UDC" > UDC

    log "Network gadget started on $UDC"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Silent Storage gadget (Storage + ACM for wake-up capability)
# Used for silent fallback mode - no network, but ACM allows serial wake-up
# ═══════════════════════════════════════════════════════════════════════════════

gadget_silent_storage() {
    log "Starting USB gadget v${VERSION} (SILENT STORAGE mode)..."

    # Clean up any existing gadget
    gadget_down

    # Create storage image if needed
    create_storage_image

    # Create gadget directory and enter it
    mkdir -p "$GADGET" && cd "$GADGET"

    # USB IDs - Use composite gadget class for Storage + ACM
    echo 0x1d6b > idVendor      # Linux Foundation
    echo 0x0104 > idProduct     # Multifunction Composite Gadget
    echo 0x0200 > bcdDevice

    # USB class: Miscellaneous (for composite device)
    echo 0xEF > bDeviceClass
    echo 0x02 > bDeviceSubClass
    echo 0x01 > bDeviceProtocol

    # Strings (0x409 = US English)
    mkdir -p strings/0x409
    echo "CyberMind SecuBox" > strings/0x409/manufacturer
    echo "Eye Remote Storage" > strings/0x409/product
    SERIAL=$(grep -oP 'Serial\s*:\s*\K[0-9a-f]+' /proc/cpuinfo 2>/dev/null || echo "0000001")
    echo "$SERIAL" > strings/0x409/serialnumber

    # Function 1: Mass Storage
    mkdir -p functions/mass_storage.usb0/lun.0
    echo 1 > functions/mass_storage.usb0/lun.0/removable
    echo 0 > functions/mass_storage.usb0/lun.0/cdrom
    echo 0 > functions/mass_storage.usb0/lun.0/ro
    echo 0 > functions/mass_storage.usb0/lun.0/nofua
    echo "$STORAGE_IMAGE" > functions/mass_storage.usb0/lun.0/file

    # Function 2: CDC-ACM (Serial console for wake-up commands)
    mkdir -p functions/acm.usb0

    # Configuration
    mkdir -p configs/c.1/strings/0x409
    echo "SecuBox Eye Remote (Storage + ACM)" > configs/c.1/strings/0x409/configuration
    echo 200 > configs/c.1/MaxPower

    # Link functions to configuration
    ln -sf functions/mass_storage.usb0 configs/c.1/
    ln -sf functions/acm.usb0 configs/c.1/

    # Bind to UDC
    UDC=$(ls /sys/class/udc/ | head -1)
    if [[ -z "$UDC" ]]; then
        log "ERROR: No UDC found"
        return 1
    fi
    echo "$UDC" > UDC

    log "Silent storage gadget started on $UDC"
    log "Storage: $STORAGE_IMAGE"
    log "Serial console (for wake): /dev/ttyGS0"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════

case "${1:-}" in
    up|start)
        # Direct start (boot time, no mode switch delay needed)
        gadget_up
        ;;
    down|stop)
        # Direct stop (no lock needed)
        gadget_down
        ;;
    status)
        # Query only, no lock needed
        gadget_status
        ;;
    storage|uboot|hid|keyboard|network|ecm|silent|silent-storage)
        # Mode switches use safe transition with lock and delay
        safe_mode_switch "$1"
        ;;
    --force-*)
        # Force mode without safety delay (for recovery)
        mode="${1#--force-}"
        log "Force mode: $mode (no delay)"
        gadget_down
        case "$mode" in
            up)      gadget_up ;;
            network) gadget_network ;;
            hid)     gadget_hid ;;
            storage) gadget_storage_only ;;
            silent)  gadget_silent_storage ;;
        esac
        ;;
    *)
        echo "Usage: $0 {up|down|status|storage|hid|network|silent}"
        echo ""
        echo "Commands:"
        echo "  up|start      - Start composite gadget (ECM + ACM + Storage)"
        echo "  down|stop     - Stop gadget"
        echo "  status        - Show gadget status (JSON)"
        echo "  storage|uboot - Start storage-only gadget (for U-Boot compatibility)"
        echo "  hid|keyboard  - Start HID keyboard + ACM gadget"
        echo "  network|ecm   - Start network-only gadget (ECM + ACM, no storage)"
        echo "  silent        - Start silent storage + ACM (for fallback mode)"
        echo ""
        echo "Safe Mode Switch:"
        echo "  Mode changes include a ${SWITCH_DELAY}s delay for USB bus stability"
        echo "  Use --force-<mode> to skip delay (recovery only)"
        echo ""
        echo "Auto-Mode Priority (highest to lowest):"
        echo "  1. network  - ECM + ACM (requires host network support)"
        echo "  2. hid      - HID Keyboard + ACM (fallback when network fails)"
        echo "  3. storage  - Mass Storage + ACM (recovery, U-Boot compatible)"
        echo ""
        echo "Note: U-Boot has limited support for composite USB gadgets."
        echo "Use 'storage' mode when flashing from U-Boot."
        exit 1
        ;;
esac
