#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# SecuBox-Deb :: gadget-setup.sh
# CyberMind — Gérald Kerma
#
# USB Gadget configuration manager for SecuBox Eye Remote
# Manages libcomposite configfs for ECM + ACM + mass_storage
#
# Subcommands:
#   up / start         → Create gadget tree, attach functions, bind UDC
#   down / stop        → Unbind UDC, tear down cleanly
#   swap-lun <path>    → Eject and re-attach mass storage LUN
#   status             → JSON output with UDC and function state
#
# License: Proprietary / ANSSI CSPN candidate
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

readonly MODULE="eye-remote"
readonly VERSION="2.1.0"

# ═══════════════════════════════════════════════════════════════════════════════
# Configuration Constants
# ═══════════════════════════════════════════════════════════════════════════════

readonly CONFIGFS="/sys/kernel/config/usb_gadget"
readonly GADGET_NAME="secubox"
readonly GADGET_PATH="${CONFIGFS}/${GADGET_NAME}"

# USB Device IDs (Linux Foundation multifunction composite gadget)
readonly ID_VENDOR="0x1d6b"
readonly ID_PRODUCT="0x0104"
readonly BCD_DEVICE="0x0210"

# Boot media directory
readonly BOOT_MEDIA_DIR="/var/lib/secubox/eye-remote/boot-media"
readonly BOOT_MEDIA_ACTIVE="${BOOT_MEDIA_DIR}/active"

# Logging
log()  { echo "[${MODULE}-gadget] $*"; logger -t "secubox-${MODULE}" "$*"; }
err()  { echo "[${MODULE}-gadget] ERROR: $*" >&2; logger -t "secubox-${MODULE}" -p err "$*"; }
debug() { [[ "${DEBUG:-0}" == "1" ]] && echo "[${MODULE}-gadget] DEBUG: $*" >&2; }

# ═══════════════════════════════════════════════════════════════════════════════
# Utility: Extract RPi serial from /proc/cpuinfo
# ═══════════════════════════════════════════════════════════════════════════════

get_serial() {
    local serial
    serial=$(grep -oP 'Serial\s*:\s*\K[0-9a-f]+' /proc/cpuinfo 2>/dev/null || echo "0000000000000000")
    echo "${serial}"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Utility: Generate deterministic MAC from serial
# ═══════════════════════════════════════════════════════════════════════════════

generate_mac() {
    local serial="$1"
    local offset="$2"

    # Use last 12 hex chars of serial (6 bytes)
    local base_hex="${serial: -12}"

    # Add offset to last byte
    local last_byte=$((16#${base_hex: -2} + offset))
    last_byte=$((last_byte % 256))
    local last_hex
    last_hex=$(printf "%02x" "$last_byte")

    # Format: 02:sb:XX:XX:XX:XX (02 = locally administered, sb = SecuBox)
    printf "02:sb:%s:%s:%s:%s" \
        "${base_hex:0:2}" "${base_hex:2:2}" "${base_hex:4:2}" "$last_hex"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Utility: Check prerequisites
# ═══════════════════════════════════════════════════════════════════════════════

check_prerequisites() {
    # Must be root
    if [[ $EUID -ne 0 ]]; then
        err "This script must be run as root"
        return 1
    fi

    # Ensure configfs is mounted
    if [[ ! -d "$CONFIGFS" ]]; then
        debug "Mounting configfs..."
        modprobe configfs 2>/dev/null || true
        mount -t configfs none /sys/kernel/config 2>/dev/null || true

        if [[ ! -d "$CONFIGFS" ]]; then
            err "configfs not available"
            return 1
        fi
    fi

    # Load required kernel modules
    modprobe libcomposite 2>/dev/null || true
    modprobe usb_f_ecm 2>/dev/null || true
    modprobe usb_f_acm 2>/dev/null || true
    modprobe usb_f_mass_storage 2>/dev/null || true

    # Wait for UDC to become available (dwc2 needs time to initialize)
    # This is critical at boot when the service starts before dwc2 is ready
    local udc_list=""
    local wait_count=0
    local max_wait=30  # 30 × 0.5s = 15 seconds max

    log "Waiting for UDC (USB Device Controller)..."
    while [[ -z "$udc_list" ]] && [[ $wait_count -lt $max_wait ]]; do
        udc_list=$(ls /sys/class/udc/ 2>/dev/null | head -1)
        if [[ -z "$udc_list" ]]; then
            sleep 0.5
            ((wait_count++))
            [[ $((wait_count % 4)) -eq 0 ]] && debug "Still waiting for UDC... (${wait_count}/${max_wait})"
        fi
    done

    if [[ -z "$udc_list" ]]; then
        err "No UDC found after ${max_wait} attempts (this script requires RPi Zero W)"
        err "Check: dtoverlay=dwc2 in /boot/firmware/config.txt"
        return 1
    fi

    log "UDC detected: $udc_list (after $((wait_count)) waits)"
    return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# Create USB gadget with ECM + ACM + mass_storage
# ═══════════════════════════════════════════════════════════════════════════════

gadget_up() {
    log "Starting SecuBox Eye Remote USB gadget v${VERSION}..."

    # Check if already running
    if [[ -d "$GADGET_PATH" ]]; then
        log "Gadget already configured, cleaning up first..."
        gadget_down || true
        sleep 0.5
    fi

    # Check prerequisites
    if ! check_prerequisites; then
        err "Prerequisites check failed"
        return 1
    fi

    # Get serial and generate MAC addresses
    local serial mac_host mac_dev
    serial=$(get_serial)
    mac_host=$(generate_mac "$serial" 0)
    mac_dev=$(generate_mac "$serial" 1)

    debug "RPi Serial: ${serial}"
    debug "MAC host (SecuBox): ${mac_host}"
    debug "MAC device (Eye Remote): ${mac_dev}"

    # Create gadget directory
    mkdir -p "$GADGET_PATH"
    cd "$GADGET_PATH"

    # Basic USB IDs
    echo "$ID_VENDOR"  > idVendor
    echo "$ID_PRODUCT" > idProduct
    echo "$BCD_DEVICE" > bcdDevice

    # USB class: Miscellaneous (for composite device)
    echo 0xEF > bDeviceClass
    echo 0x02 > bDeviceSubClass
    echo 0x01 > bDeviceProtocol

    # Strings (0x409 = US English)
    mkdir -p strings/0x409
    echo "CyberMind SecuBox" > strings/0x409/manufacturer
    echo "Eye Remote Bootstrap" > strings/0x409/product
    echo "$serial" > strings/0x409/serialnumber

    # ──── Function 1: CDC-ECM (Ethernet for Linux/macOS) ────────────────────────
    debug "Creating ECM function..."
    mkdir -p functions/ecm.usb0
    echo "$mac_host" > functions/ecm.usb0/host_addr
    echo "$mac_dev" > functions/ecm.usb0/dev_addr

    # ──── Function 2: CDC-ACM (Virtual serial console) ──────────────────────────
    debug "Creating ACM function..."
    mkdir -p functions/acm.usb0

    # ──── Function 3: Mass Storage (Boot media LUN) - OPTIONAL ─────────────────
    # Mass storage is optional - if it fails, continue with ECM+ACM only
    local mass_storage_ok=false
    mkdir -p "$BOOT_MEDIA_DIR"

    # Resolve symlink to actual file path (kernel configfs doesn't follow symlinks)
    local boot_media_file=""
    if [[ -L "$BOOT_MEDIA_ACTIVE" ]]; then
        boot_media_file=$(readlink -f "$BOOT_MEDIA_ACTIVE" 2>/dev/null || true)
    elif [[ -f "$BOOT_MEDIA_ACTIVE" ]]; then
        boot_media_file="$BOOT_MEDIA_ACTIVE"
    fi

    # Only setup mass_storage if we have a valid backing file with actual content
    if [[ -n "$boot_media_file" ]] && [[ -f "$boot_media_file" ]] && [[ -s "$boot_media_file" ]]; then
        debug "Setting up mass_storage with: $boot_media_file"
        if mkdir -p functions/mass_storage.usb0 2>/dev/null; then
            if echo "$boot_media_file" > functions/mass_storage.usb0/lun.0/file 2>/dev/null; then
                echo 1 > functions/mass_storage.usb0/lun.0/removable 2>/dev/null || true
                echo 0 > functions/mass_storage.usb0/lun.0/ro 2>/dev/null || true
                echo 0 > functions/mass_storage.usb0/lun.0/cdrom 2>/dev/null || true
                echo 0 > functions/mass_storage.usb0/lun.0/nofua 2>/dev/null || true
                mass_storage_ok=true
                debug "mass_storage configured successfully"
            else
                log "WARNING: mass_storage LUN file write failed, continuing without it"
                rmdir functions/mass_storage.usb0 2>/dev/null || true
            fi
        fi
    else
        log "No valid boot media, skipping mass_storage (ECM+ACM only)"
    fi

    # ──── Create composite configuration ──────────────────────────────────────
    debug "Creating composite configuration..."
    mkdir -p configs/c.1/strings/0x409
    if [[ "$mass_storage_ok" == "true" ]]; then
        echo "SecuBox Eye Remote (ECM + ACM + Mass Storage)" > configs/c.1/strings/0x409/configuration
    else
        echo "SecuBox Eye Remote (ECM + ACM)" > configs/c.1/strings/0x409/configuration
    fi
    echo 500 > configs/c.1/MaxPower  # 500 mA

    # Link functions to configuration
    ln -sf ../../functions/ecm.usb0 configs/c.1/
    ln -sf ../../functions/acm.usb0 configs/c.1/
    if [[ "$mass_storage_ok" == "true" ]]; then
        ln -sf ../../functions/mass_storage.usb0 configs/c.1/
    fi

    # ──── Bind to UDC ────────────────────────────────────────────────────────
    local udc
    udc=$(ls /sys/class/udc/ 2>/dev/null | head -1)
    if [[ -z "$udc" ]]; then
        err "No UDC found for binding"
        return 1
    fi

    debug "Binding to UDC: ${udc}"
    echo "$udc" > UDC

    # Wait for usb1 (ECM) interface to appear
    # Note: Composite gadget creates usb0 (RNDIS/Windows) and usb1 (ECM/Linux-Mac)
    # Linux hosts use cdc_ether driver which maps to usb1
    local retry=0
    while [[ ! -d /sys/class/net/usb1 ]] && [[ $retry -lt 10 ]]; do
        sleep 0.5
        ((retry++))
    done

    if [[ -d /sys/class/net/usb1 ]]; then
        debug "Interface usb1 (ECM) created"

        # Configure IP on usb1 only (avoids asymmetric routing with same IP on both)
        ip addr flush dev usb1 2>/dev/null || true
        ip addr add 10.55.0.2/30 dev usb1
        ip link set usb1 up
        debug "usb1 configured: 10.55.0.2/30"
    else
        err "Interface usb1 did not appear after 5s"
        return 1
    fi

    # Verify ttyGS0 (may not exist yet if not yet connected to host)
    if [[ -c /dev/ttyGS0 ]]; then
        debug "Serial console /dev/ttyGS0 available"
    else
        debug "Serial console /dev/ttyGS0 not available yet (will appear on host connection)"
    fi

    log "USB gadget started successfully (UDC: ${udc})"
    return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# Tear down USB gadget cleanly
# ═══════════════════════════════════════════════════════════════════════════════

gadget_down() {
    log "Stopping SecuBox Eye Remote USB gadget..."

    if [[ ! -d "$GADGET_PATH" ]]; then
        log "Gadget not configured"
        return 0
    fi

    cd "$GADGET_PATH"

    # Unbind from UDC
    if [[ -f UDC ]] && [[ -n "$(cat UDC 2>/dev/null || true)" ]]; then
        debug "Unbinding from UDC..."
        echo "" > UDC
        sleep 0.5
    fi

    # Remove function links from configuration
    rm -f configs/c.1/ecm.usb0 2>/dev/null || true
    rm -f configs/c.1/acm.usb0 2>/dev/null || true
    rm -f configs/c.1/mass_storage.usb0 2>/dev/null || true

    # Remove configuration strings directory
    rmdir configs/c.1/strings/0x409 2>/dev/null || true

    # Remove configuration
    rmdir configs/c.1 2>/dev/null || true

    # Remove functions
    rmdir functions/ecm.usb0 2>/dev/null || true
    rmdir functions/acm.usb0 2>/dev/null || true
    rmdir functions/mass_storage.usb0 2>/dev/null || true

    # Remove gadget strings
    rmdir strings/0x409 2>/dev/null || true

    # Remove gadget root directory
    cd /
    rmdir "$GADGET_PATH" 2>/dev/null || true

    log "USB gadget stopped"
    return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# Eject and re-attach mass storage LUN (for boot media swaps)
# ═══════════════════════════════════════════════════════════════════════════════

lun_swap() {
    local new_path="$1"

    if [[ ! -f "$GADGET_PATH/functions/mass_storage.usb0/lun.0/file" ]]; then
        err "Mass storage LUN not found"
        return 1
    fi

    if [[ ! -f "$new_path" ]]; then
        err "Boot media file not found: $new_path"
        return 1
    fi

    log "Swapping LUN to: $new_path"

    # Eject current backing file
    debug "Ejecting current LUN..."
    echo "" > "$GADGET_PATH/functions/mass_storage.usb0/lun.0/file"
    sleep 0.1

    # Re-attach with new backing file
    debug "Attaching new backing file..."
    echo "$new_path" > "$GADGET_PATH/functions/mass_storage.usb0/lun.0/file"

    log "LUN swapped successfully"
    return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# Output JSON status
# ═══════════════════════════════════════════════════════════════════════════════

gadget_status() {
    local udc_status="unbound"
    local ecm_active="false"
    local acm_active="false"
    local mass_storage_active="false"
    local lun_file=""

    if [[ -d "$GADGET_PATH" ]]; then
        if [[ -f "$GADGET_PATH/UDC" ]] && [[ -n "$(cat "$GADGET_PATH/UDC" 2>/dev/null || true)" ]]; then
            udc_status="$(cat "$GADGET_PATH/UDC")"
            ecm_active="true"
            acm_active="true"
            mass_storage_active="true"
        fi

        if [[ -f "$GADGET_PATH/functions/mass_storage.usb0/lun.0/file" ]]; then
            lun_file="$(cat "$GADGET_PATH/functions/mass_storage.usb0/lun.0/file" 2>/dev/null || echo "")"
        fi
    fi

    # Output JSON
    cat <<EOF
{
  "gadget_configured": $([ -d "$GADGET_PATH" ] && echo "true" || echo "false"),
  "udc_status": "$udc_status",
  "functions": {
    "ecm": $ecm_active,
    "acm": $acm_active,
    "mass_storage": $mass_storage_active
  },
  "mass_storage": {
    "lun_file": "$lun_file",
    "file_exists": $([ -f "$lun_file" ] && echo "true" || echo "false")
  }
}
EOF
    return 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# Main entry point
# ═══════════════════════════════════════════════════════════════════════════════

main() {
    local cmd="${1:-}"

    case "$cmd" in
        up|start)
            gadget_up
            ;;
        down|stop)
            gadget_down
            ;;
        swap-lun)
            if [[ -z "${2:-}" ]]; then
                err "swap-lun requires a path argument"
                return 1
            fi
            lun_swap "$2"
            ;;
        status)
            gadget_status
            ;;
        "")
            err "Missing subcommand"
            echo "Usage: $0 {up|down|swap-lun <path>|status}"
            return 1
            ;;
        *)
            err "Unknown subcommand: $cmd"
            echo "Usage: $0 {up|down|swap-lun <path>|status}"
            return 1
            ;;
    esac
}

main "$@"
