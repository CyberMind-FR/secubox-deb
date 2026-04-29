#!/usr/bin/env bash
# SecuBox Eye Remote - Gadget Mode Switch Script
# CyberMind — Gerald Kerma
# Switches USB gadget mode via configfs/libcomposite

set -euo pipefail

readonly SCRIPT_NAME="eye-gadget-switch"
readonly VERSION="1.0.0"

# ConfigFS paths
readonly CONFIGFS="/sys/kernel/config/usb_gadget"
readonly GADGET_NAME="secubox"
readonly GADGET_PATH="${CONFIGFS}/${GADGET_NAME}"

# Default configuration (can be overridden via environment)
GADGET_VENDOR_ID="${GADGET_VENDOR_ID:-0x1d6b}"
GADGET_PRODUCT_ID="${GADGET_PRODUCT_ID:-0x0104}"
GADGET_MANUFACTURER="${GADGET_MANUFACTURER:-SecuBox}"
GADGET_PRODUCT="${GADGET_PRODUCT:-Eye Remote}"
GADGET_SERIAL="${GADGET_SERIAL:-}"

ECM_HOST_IP="${ECM_HOST_IP:-10.55.0.1}"
ECM_DEVICE_IP="${ECM_DEVICE_IP:-10.55.0.2}"
ECM_HOST_MAC="${ECM_HOST_MAC:-}"
ECM_DEVICE_MAC="${ECM_DEVICE_MAC:-}"

ACM_BAUDRATE="${ACM_BAUDRATE:-115200}"

STORAGE_FILE="${STORAGE_FILE:-/srv/eye-remote/storage.img}"
STORAGE_READONLY="${STORAGE_READONLY:-0}"

# Get serial from cpuinfo
get_serial() {
    grep -oP 'Serial\s*:\s*\K[0-9a-fA-F]+' /proc/cpuinfo 2>/dev/null | tail -c 9 || echo "00000000"
}

# Generate deterministic MAC from serial
generate_mac() {
    local prefix="${1:-02:00:00}"
    local serial
    serial=$(get_serial)
    echo "${prefix}:${serial:2:2}:${serial:4:2}:${serial:6:2}"
}

# Find available UDC
find_udc() {
    local udc_dir="/sys/class/udc"
    if [[ -d "$udc_dir" ]]; then
        ls "$udc_dir" 2>/dev/null | head -1
    fi
}

# Get current UDC binding
get_current_udc() {
    if [[ -f "${GADGET_PATH}/UDC" ]]; then
        cat "${GADGET_PATH}/UDC" 2>/dev/null | tr -d '\n'
    fi
}

# Unbind gadget from UDC
unbind_gadget() {
    local current_udc
    current_udc=$(get_current_udc)
    if [[ -n "$current_udc" ]]; then
        echo "" > "${GADGET_PATH}/UDC" 2>/dev/null || true
        sleep 0.1
    fi
}

# Remove function symlinks from config
clear_functions() {
    local config_path="${GADGET_PATH}/configs/c.1"
    if [[ -d "$config_path" ]]; then
        for link in "$config_path"/*; do
            if [[ -L "$link" ]]; then
                rm -f "$link" 2>/dev/null || true
            fi
        done
    fi
}

# Create gadget structure if needed
ensure_gadget_structure() {
    # Load modules
    modprobe libcomposite 2>/dev/null || true

    # Create gadget directory
    if [[ ! -d "$GADGET_PATH" ]]; then
        mkdir -p "$GADGET_PATH"
    fi

    # Set USB IDs
    echo "${GADGET_VENDOR_ID}" > "${GADGET_PATH}/idVendor" 2>/dev/null || true
    echo "${GADGET_PRODUCT_ID}" > "${GADGET_PATH}/idProduct" 2>/dev/null || true
    echo "0x0200" > "${GADGET_PATH}/bcdUSB" 2>/dev/null || true
    echo "0xEF" > "${GADGET_PATH}/bDeviceClass" 2>/dev/null || true
    echo "0x02" > "${GADGET_PATH}/bDeviceSubClass" 2>/dev/null || true
    echo "0x01" > "${GADGET_PATH}/bDeviceProtocol" 2>/dev/null || true

    # Create strings directory
    local strings_path="${GADGET_PATH}/strings/0x409"
    mkdir -p "$strings_path" 2>/dev/null || true

    # Set serial if not provided
    [[ -z "$GADGET_SERIAL" ]] && GADGET_SERIAL=$(get_serial)

    echo "$GADGET_SERIAL" > "${strings_path}/serialnumber" 2>/dev/null || true
    echo "$GADGET_MANUFACTURER" > "${strings_path}/manufacturer" 2>/dev/null || true
    echo "$GADGET_PRODUCT" > "${strings_path}/product" 2>/dev/null || true

    # Create config
    local config_path="${GADGET_PATH}/configs/c.1"
    mkdir -p "$config_path" 2>/dev/null || true
    mkdir -p "${config_path}/strings/0x409" 2>/dev/null || true
    echo "SecuBox Config" > "${config_path}/strings/0x409/configuration" 2>/dev/null || true
    echo 250 > "${config_path}/MaxPower" 2>/dev/null || true
}

# Create ECM function
create_ecm_function() {
    local func_path="${GADGET_PATH}/functions/ecm.usb0"

    if [[ ! -d "$func_path" ]]; then
        mkdir -p "$func_path"
    fi

    # Set MAC addresses
    [[ -z "$ECM_HOST_MAC" ]] && ECM_HOST_MAC=$(generate_mac "02:00:00")
    [[ -z "$ECM_DEVICE_MAC" ]] && ECM_DEVICE_MAC=$(generate_mac "02:00:01")

    echo "$ECM_HOST_MAC" > "${func_path}/host_addr" 2>/dev/null || true
    echo "$ECM_DEVICE_MAC" > "${func_path}/dev_addr" 2>/dev/null || true
}

# Create ACM function
create_acm_function() {
    local func_path="${GADGET_PATH}/functions/acm.usb0"

    if [[ ! -d "$func_path" ]]; then
        mkdir -p "$func_path"
    fi
}

# Create Mass Storage function
create_mass_storage_function() {
    local func_path="${GADGET_PATH}/functions/mass_storage.usb0"
    local lun_path="${func_path}/lun.0"

    if [[ ! -d "$func_path" ]]; then
        mkdir -p "$func_path"
    fi

    if [[ ! -d "$lun_path" ]]; then
        mkdir -p "$lun_path" 2>/dev/null || true
    fi

    # Create storage file if needed
    if [[ ! -f "$STORAGE_FILE" ]]; then
        local storage_dir
        storage_dir=$(dirname "$STORAGE_FILE")
        mkdir -p "$storage_dir" 2>/dev/null || true
        # Create 64MB storage file
        dd if=/dev/zero of="$STORAGE_FILE" bs=1M count=64 2>/dev/null || true
        mkfs.vfat "$STORAGE_FILE" 2>/dev/null || true
    fi

    # Set storage parameters
    echo "$STORAGE_FILE" > "${lun_path}/file" 2>/dev/null || true
    echo "$STORAGE_READONLY" > "${lun_path}/ro" 2>/dev/null || true
    echo "1" > "${lun_path}/removable" 2>/dev/null || true
    echo "0" > "${lun_path}/cdrom" 2>/dev/null || true
}

# Link function to config
link_function() {
    local func_name="$1"
    local config_path="${GADGET_PATH}/configs/c.1"
    local func_path="${GADGET_PATH}/functions/${func_name}"

    if [[ -d "$func_path" && ! -L "${config_path}/${func_name}" ]]; then
        ln -sf "$func_path" "${config_path}/${func_name}"
    fi
}

# Bind gadget to UDC
bind_gadget() {
    local udc
    udc=$(find_udc)

    if [[ -z "$udc" ]]; then
        echo "ERROR: No UDC found" >&2
        return 1
    fi

    echo "$udc" > "${GADGET_PATH}/UDC"
    sleep 0.2
}

# Configure network after ECM is up
configure_ecm_network() {
    local iface="usb0"
    local max_wait=5
    local count=0

    # Wait for interface
    while [[ ! -d "/sys/class/net/${iface}" && $count -lt $max_wait ]]; do
        sleep 0.5
        ((count++))
    done

    if [[ -d "/sys/class/net/${iface}" ]]; then
        ip addr add "${ECM_DEVICE_IP}/30" dev "$iface" 2>/dev/null || true
        ip link set "$iface" up 2>/dev/null || true
    fi
}

# Switch to specified mode
switch_mode() {
    local mode="$1"

    echo "Switching to mode: $mode"

    # Unbind current gadget
    unbind_gadget

    # Clear existing functions
    clear_functions

    # Ensure base structure
    ensure_gadget_structure

    case "$mode" in
        none)
            echo "Gadget disabled"
            return 0
            ;;
        ecm)
            create_ecm_function
            link_function "ecm.usb0"
            ;;
        acm)
            create_acm_function
            link_function "acm.usb0"
            ;;
        mass_storage)
            create_mass_storage_function
            link_function "mass_storage.usb0"
            ;;
        composite)
            create_ecm_function
            create_acm_function
            create_mass_storage_function
            link_function "ecm.usb0"
            link_function "acm.usb0"
            link_function "mass_storage.usb0"
            ;;
        *)
            echo "ERROR: Invalid mode: $mode" >&2
            echo "Valid modes: none, ecm, acm, mass_storage, composite" >&2
            return 1
            ;;
    esac

    # Bind to UDC
    bind_gadget

    # Configure network for ECM modes
    if [[ "$mode" == "ecm" || "$mode" == "composite" ]]; then
        configure_ecm_network &
    fi

    echo "Switched to $mode mode"
    return 0
}

# Show current status
show_status() {
    echo "=== SecuBox Eye Remote Gadget Status ==="
    echo

    local udc
    udc=$(get_current_udc)

    if [[ -z "$udc" ]]; then
        echo "Status: Unbound"
    else
        echo "Status: Bound to $udc"
    fi

    echo
    echo "Active functions:"
    local config_path="${GADGET_PATH}/configs/c.1"
    if [[ -d "$config_path" ]]; then
        for link in "$config_path"/*; do
            if [[ -L "$link" ]]; then
                echo "  - $(basename "$link")"
            fi
        done
    fi

    echo
    echo "Network interface:"
    if [[ -d "/sys/class/net/usb0" ]]; then
        ip addr show usb0 2>/dev/null | grep -E "inet |link/ether" | sed 's/^/  /'
    else
        echo "  Not available"
    fi
}

# Main
main() {
    if [[ $# -lt 1 ]]; then
        echo "Usage: $SCRIPT_NAME <mode|status>"
        echo "Modes: none, ecm, acm, mass_storage, composite"
        exit 1
    fi

    local cmd="$1"

    # Check root
    if [[ $EUID -ne 0 && "$cmd" != "status" ]]; then
        echo "ERROR: Root privileges required" >&2
        exit 1
    fi

    case "$cmd" in
        status)
            show_status
            ;;
        none|ecm|acm|mass_storage|composite)
            switch_mode "$cmd"
            ;;
        *)
            echo "ERROR: Unknown command: $cmd" >&2
            exit 1
            ;;
    esac
}

main "$@"
