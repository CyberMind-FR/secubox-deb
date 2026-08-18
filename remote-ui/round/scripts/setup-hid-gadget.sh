#!/bin/bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# ═══════════════════════════════════════════════════════════════════════════════
# SecuBox Eye Remote — HID Keyboard Gadget Setup
# CyberMind — Gérald Kerma
#
# Sets up USB HID keyboard gadget for Eye Remote.
# Used as fallback when host doesn't support CDC-ECM networking.
# Allows typing commands into U-Boot console or other systems.
#
# Usage: setup-hid-gadget.sh {setup|teardown|status|test}
#
# License: Proprietary / ANSSI CSPN candidate
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

readonly VERSION="1.0.0"
readonly GADGET="/sys/kernel/config/usb_gadget/secubox-hid"
readonly HID_DEV="/dev/hidg0"

log() { echo "[hid-gadget] $*"; logger -t hid-gadget "$*"; }
err() { echo "[hid-gadget] ERROR: $*" >&2; logger -t hid-gadget -p err "$*"; }

# ═══════════════════════════════════════════════════════════════════════════════
# HID Keyboard Report Descriptor (boot protocol keyboard - 8 bytes)
# ═══════════════════════════════════════════════════════════════════════════════

write_keyboard_report_desc() {
    local path="$1"

    # Standard boot keyboard report descriptor
    # Report format: [modifier][reserved][key1][key2][key3][key4][key5][key6]
    echo -ne '\x05\x01'      > "$path"   # Usage Page (Generic Desktop)
    echo -ne '\x09\x06'     >> "$path"   # Usage (Keyboard)
    echo -ne '\xa1\x01'     >> "$path"   # Collection (Application)
    echo -ne '\x05\x07'     >> "$path"   #   Usage Page (Key Codes)
    echo -ne '\x19\xe0'     >> "$path"   #   Usage Minimum (224) - Left Control
    echo -ne '\x29\xe7'     >> "$path"   #   Usage Maximum (231) - Right GUI
    echo -ne '\x15\x00'     >> "$path"   #   Logical Minimum (0)
    echo -ne '\x25\x01'     >> "$path"   #   Logical Maximum (1)
    echo -ne '\x75\x01'     >> "$path"   #   Report Size (1)
    echo -ne '\x95\x08'     >> "$path"   #   Report Count (8)
    echo -ne '\x81\x02'     >> "$path"   #   Input (Data, Variable, Absolute) - Modifier byte
    echo -ne '\x95\x01'     >> "$path"   #   Report Count (1)
    echo -ne '\x75\x08'     >> "$path"   #   Report Size (8)
    echo -ne '\x81\x01'     >> "$path"   #   Input (Constant) - Reserved byte
    echo -ne '\x95\x06'     >> "$path"   #   Report Count (6)
    echo -ne '\x75\x08'     >> "$path"   #   Report Size (8)
    echo -ne '\x15\x00'     >> "$path"   #   Logical Minimum (0)
    echo -ne '\x25\x65'     >> "$path"   #   Logical Maximum (101)
    echo -ne '\x05\x07'     >> "$path"   #   Usage Page (Key Codes)
    echo -ne '\x19\x00'     >> "$path"   #   Usage Minimum (0)
    echo -ne '\x29\x65'     >> "$path"   #   Usage Maximum (101)
    echo -ne '\x81\x00'     >> "$path"   #   Input (Data, Array) - Key array
    echo -ne '\xc0'         >> "$path"   # End Collection
}

# ═══════════════════════════════════════════════════════════════════════════════
# Setup HID Gadget
# ═══════════════════════════════════════════════════════════════════════════════

setup_gadget() {
    log "Setting up HID keyboard gadget v${VERSION}..."

    # Check prerequisites
    if [[ $EUID -ne 0 ]]; then
        err "Root privileges required"
        return 1
    fi

    # Load required modules
    modprobe configfs 2>/dev/null || true
    modprobe libcomposite 2>/dev/null || true
    modprobe usb_f_hid 2>/dev/null || true

    # Mount configfs if needed
    if [[ ! -d /sys/kernel/config ]]; then
        mount -t configfs none /sys/kernel/config
    fi

    # Clean up existing gadget
    teardown_gadget 2>/dev/null || true

    # Create gadget directory
    mkdir -p "$GADGET" && cd "$GADGET"

    # USB IDs
    echo 0x1d6b > idVendor      # Linux Foundation
    echo 0x0104 > idProduct     # Multifunction Composite Gadget
    echo 0x0200 > bcdDevice
    echo 0x0200 > bcdUSB

    # Device class: defined at interface level
    echo 0x00 > bDeviceClass
    echo 0x00 > bDeviceSubClass
    echo 0x00 > bDeviceProtocol

    # Strings
    mkdir -p strings/0x409
    echo "CyberMind SecuBox" > strings/0x409/manufacturer
    echo "Eye Remote Keyboard" > strings/0x409/product
    SERIAL=$(grep -oP 'Serial\s*:\s*\K[0-9a-f]+' /proc/cpuinfo 2>/dev/null || echo "0000001")
    echo "$SERIAL" > strings/0x409/serialnumber

    # HID function
    mkdir -p functions/hid.usb0
    echo 1 > functions/hid.usb0/protocol      # Keyboard protocol
    echo 1 > functions/hid.usb0/subclass      # Boot interface subclass
    echo 8 > functions/hid.usb0/report_length # 8 bytes per report
    write_keyboard_report_desc functions/hid.usb0/report_desc

    # Configuration
    mkdir -p configs/c.1/strings/0x409
    echo "HID Keyboard" > configs/c.1/strings/0x409/configuration
    echo 100 > configs/c.1/MaxPower

    # Link function
    ln -sf functions/hid.usb0 configs/c.1/

    # Bind to UDC
    UDC=$(ls /sys/class/udc/ | head -1)
    if [[ -z "$UDC" ]]; then
        err "No UDC found"
        return 1
    fi
    echo "$UDC" > UDC

    # Wait for device
    sleep 0.5
    if [[ -c "$HID_DEV" ]]; then
        log "HID keyboard gadget ready: $HID_DEV"
    else
        err "HID device not created"
        return 1
    fi

    log "HID gadget setup complete on $UDC"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Teardown HID Gadget
# ═══════════════════════════════════════════════════════════════════════════════

teardown_gadget() {
    [[ -d "$GADGET" ]] || return 0

    log "Tearing down HID gadget..."

    cd "$GADGET" 2>/dev/null || true

    # Unbind UDC
    echo "" > UDC 2>/dev/null || true

    # Remove function links
    rm -f configs/c.1/hid.usb0 2>/dev/null || true

    # Remove config strings
    rmdir configs/c.1/strings/0x409 2>/dev/null || true

    # Remove config
    rmdir configs/c.1 2>/dev/null || true

    # Remove function
    rmdir functions/hid.usb0 2>/dev/null || true

    # Remove gadget strings
    rmdir strings/0x409 2>/dev/null || true

    # Remove gadget
    cd /
    rmdir "$GADGET" 2>/dev/null || true

    log "HID gadget teardown complete"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Status
# ═══════════════════════════════════════════════════════════════════════════════

show_status() {
    echo "=== HID Keyboard Gadget Status ==="

    if [[ -d "$GADGET" ]]; then
        echo "Gadget:     CONFIGURED"
        if [[ -f "$GADGET/UDC" ]] && [[ -n "$(cat "$GADGET/UDC" 2>/dev/null)" ]]; then
            echo "UDC:        $(cat "$GADGET/UDC")"
            echo "Bound:      YES"
        else
            echo "Bound:      NO"
        fi
    else
        echo "Gadget:     NOT CONFIGURED"
    fi

    if [[ -c "$HID_DEV" ]]; then
        echo "Device:     $HID_DEV (ready)"
    else
        echo "Device:     NOT AVAILABLE"
    fi

    echo ""
}

# ═══════════════════════════════════════════════════════════════════════════════
# Test - Send test keystrokes
# ═══════════════════════════════════════════════════════════════════════════════

test_keyboard() {
    if [[ ! -c "$HID_DEV" ]]; then
        err "HID device not available. Run 'setup' first."
        return 1
    fi

    log "Sending test keystroke 'H' to $HID_DEV..."

    # HID keyboard report format:
    # Byte 0: Modifier keys (Ctrl, Shift, Alt, GUI)
    # Byte 1: Reserved (always 0)
    # Bytes 2-7: Key codes (up to 6 simultaneous keys)

    # Key codes: a=4, b=5, ..., h=11, ...

    # Press 'H' (key code 11, with Shift modifier for uppercase)
    # Modifier: 0x02 = Left Shift
    echo -ne '\x02\x00\x0b\x00\x00\x00\x00\x00' > "$HID_DEV"

    # Release all keys
    sleep 0.1
    echo -ne '\x00\x00\x00\x00\x00\x00\x00\x00' > "$HID_DEV"

    log "Test keystroke sent"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Send String - Type a string via HID keyboard
# ═══════════════════════════════════════════════════════════════════════════════

send_string() {
    local text="$1"

    if [[ ! -c "$HID_DEV" ]]; then
        err "HID device not available"
        return 1
    fi

    log "Typing string: '$text'"

    # ASCII to HID keycode mapping (simplified)
    # This only handles basic alphanumeric characters
    declare -A KEYMAP=(
        [a]=4  [b]=5  [c]=6  [d]=7  [e]=8  [f]=9  [g]=10 [h]=11
        [i]=12 [j]=13 [k]=14 [l]=15 [m]=16 [n]=17 [o]=18 [p]=19
        [q]=20 [r]=21 [s]=22 [t]=23 [u]=24 [v]=25 [w]=26 [x]=27
        [y]=28 [z]=29
        [1]=30 [2]=31 [3]=32 [4]=33 [5]=34 [6]=35 [7]=36 [8]=37
        [9]=38 [0]=39
        [' ']=44  # Space
        ['-']=45  # Minus
        ['=']=46  # Equal
    )

    for (( i=0; i<${#text}; i++ )); do
        char="${text:$i:1}"
        lower_char=$(echo "$char" | tr '[:upper:]' '[:lower:]')

        # Check if uppercase (need shift)
        modifier=0
        if [[ "$char" =~ [A-Z] ]]; then
            modifier=2  # Left Shift
        fi

        # Get keycode
        keycode="${KEYMAP[$lower_char]:-0}"
        if [[ "$keycode" == "0" ]]; then
            log "Unknown character: '$char', skipping"
            continue
        fi

        # Send keypress
        printf "\\x%02x\\x00\\x%02x\\x00\\x00\\x00\\x00\\x00" "$modifier" "$keycode" > "$HID_DEV"

        # Release
        sleep 0.05
        echo -ne '\x00\x00\x00\x00\x00\x00\x00\x00' > "$HID_DEV"
        sleep 0.05
    done

    log "String typed"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Send Enter key
# ═══════════════════════════════════════════════════════════════════════════════

send_enter() {
    if [[ ! -c "$HID_DEV" ]]; then
        err "HID device not available"
        return 1
    fi

    # Enter key = keycode 40 (0x28)
    echo -ne '\x00\x00\x28\x00\x00\x00\x00\x00' > "$HID_DEV"
    sleep 0.05
    echo -ne '\x00\x00\x00\x00\x00\x00\x00\x00' > "$HID_DEV"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════

case "${1:-}" in
    setup|start)
        setup_gadget
        ;;
    teardown|stop)
        teardown_gadget
        ;;
    status)
        show_status
        ;;
    test)
        test_keyboard
        ;;
    send)
        if [[ -z "${2:-}" ]]; then
            echo "Usage: $0 send <string>"
            exit 1
        fi
        send_string "$2"
        ;;
    enter)
        send_enter
        ;;
    *)
        echo "Usage: $0 {setup|teardown|status|test|send <string>|enter}"
        echo ""
        echo "SecuBox Eye Remote HID Keyboard Gadget v${VERSION}"
        echo ""
        echo "Commands:"
        echo "  setup     - Configure HID keyboard gadget"
        echo "  teardown  - Remove HID gadget"
        echo "  status    - Show gadget status"
        echo "  test      - Send test keystroke 'H'"
        echo "  send      - Type a string via HID"
        echo "  enter     - Send Enter key"
        echo ""
        echo "Example:"
        echo "  $0 setup"
        echo "  $0 send 'boot usb0'"
        echo "  $0 enter"
        exit 1
        ;;
esac
