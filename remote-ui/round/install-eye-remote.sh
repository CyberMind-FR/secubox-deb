#!/bin/bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# ═══════════════════════════════════════════════════════════════════════════════
# SecuBox Eye Remote — Full Installation Script
# CyberMind — Gérald Kerma
#
# Installs and configures Eye Remote on Raspberry Pi Zero W with HyperPixel 2.1 Round
#
# Usage:
#   On mounted SD card:  sudo ./install-eye-remote.sh /mnt/piboot /mnt/piroot
#   On running Pi Zero:  sudo ./install-eye-remote.sh
#
# License: Proprietary / ANSSI CSPN candidate
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

VERSION="2.5.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()   { echo -e "${GREEN}[eye-remote]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARNING]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# ═══════════════════════════════════════════════════════════════════════════════
# Detect installation mode
# ═══════════════════════════════════════════════════════════════════════════════

if [[ $# -eq 2 ]]; then
    # SD card mode
    BOOT_DIR="$1"
    ROOT_DIR="$2"
    MODE="sdcard"
    log "Installing to SD card: boot=$BOOT_DIR root=$ROOT_DIR"
elif [[ $# -eq 0 ]] && [[ -f /proc/device-tree/model ]] && grep -q "Raspberry Pi Zero" /proc/device-tree/model 2>/dev/null; then
    # Running on Pi Zero
    BOOT_DIR="/boot/firmware"
    [[ -d "$BOOT_DIR" ]] || BOOT_DIR="/boot"
    ROOT_DIR=""
    MODE="live"
    log "Installing on live Pi Zero"
else
    echo "Usage:"
    echo "  On mounted SD card:  sudo $0 /mnt/piboot /mnt/piroot"
    echo "  On running Pi Zero:  sudo $0"
    exit 1
fi

[[ $EUID -eq 0 ]] || { error "Must run as root"; exit 1; }

# ═══════════════════════════════════════════════════════════════════════════════
# Boot configuration (config.txt)
# ═══════════════════════════════════════════════════════════════════════════════

configure_boot() {
    log "Configuring boot..."

    local config="$BOOT_DIR/config.txt"
    [[ -f "$config" ]] || { error "config.txt not found at $config"; return 1; }

    # Backup
    cp "$config" "$config.bak.$(date +%Y%m%d%H%M%S)"

    # HyperPixel 2.1 Round display (DPI mode, no touch - uses GPIO for SPI init)
    grep -q "dtoverlay=hyperpixel2r" "$config" || {
        cat >> "$config" << 'EOF'

# HyperPixel 2.1 Round Display (DPI mode)
dtoverlay=hyperpixel2r:disable-touch
enable_dpi_lcd=1
dpi_group=2
dpi_mode=87
dpi_output_format=0x7f216
dpi_timings=480 0 10 16 59 480 0 15 60 15 0 0 0 60 0 19200000 6
EOF
        log "Added HyperPixel display config"
    }

    # USB OTG gadget mode
    grep -q "dtoverlay=dwc2" "$config" || {
        echo "dtoverlay=dwc2" >> "$config"
        log "Added dwc2 overlay"
    }

    # Kernel command line
    local cmdline="$BOOT_DIR/cmdline.txt"
    if [[ -f "$cmdline" ]]; then
        # Add modules-load for USB gadget
        grep -q "modules-load=dwc2" "$cmdline" || {
            sed -i 's/$/ modules-load=dwc2,libcomposite/' "$cmdline"
            log "Added modules to cmdline"
        }

        # Disable USB autosuspend for stability
        grep -q "usbcore.autosuspend=-1" "$cmdline" || {
            sed -i 's/$/ usbcore.autosuspend=-1/' "$cmdline"
            log "Disabled USB autosuspend"
        }

        # Hide cursor for kiosk mode
        grep -q "vt.global_cursor_default=0" "$cmdline" || {
            sed -i 's/$/ vt.global_cursor_default=0/' "$cmdline"
        }
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# System configuration
# ═══════════════════════════════════════════════════════════════════════════════

configure_system() {
    log "Configuring system..."

    local root="${ROOT_DIR:-}"

    # Hostname
    echo "eye-remote" > "$root/etc/hostname"
    sed -i 's/127.0.1.1.*/127.0.1.1\teye-remote/' "$root/etc/hosts" 2>/dev/null || true

    # Modules
    grep -q "dwc2" "$root/etc/modules" 2>/dev/null || echo "dwc2" >> "$root/etc/modules"
    grep -q "libcomposite" "$root/etc/modules" 2>/dev/null || echo "libcomposite" >> "$root/etc/modules"

    # Modprobe config for USB gadget
    mkdir -p "$root/etc/modprobe.d"
    cat > "$root/etc/modprobe.d/secubox-otg.conf" << 'EOF'
# SecuBox Eye Remote USB Gadget Mode
options dwc2 dr_mode=peripheral
options usbcore autosuspend=-1
EOF

    # Network interface for USB gadget
    mkdir -p "$root/etc/network/interfaces.d"
    cat > "$root/etc/network/interfaces.d/usb0" << 'EOF'
allow-hotplug usb0
iface usb0 inet static
    address 10.55.0.2
    netmask 255.255.255.252
    gateway 10.55.0.1
EOF

    # Prevent NetworkManager from managing USB gadget interfaces
    mkdir -p "$root/etc/NetworkManager/conf.d"
    cat > "$root/etc/NetworkManager/conf.d/10-unmanage-usb-gadget.conf" << 'EOF'
# Don't let NetworkManager manage USB gadget interfaces
[keyfile]
unmanaged-devices=interface-name:usb0;interface-name:usb1
EOF

    log "System configured"
}

# ═══════════════════════════════════════════════════════════════════════════════
# pigpiod service (for LCD initialization)
# ═══════════════════════════════════════════════════════════════════════════════

install_pigpiod_config() {
    log "Configuring pigpiod..."

    local root="${ROOT_DIR:-}"

    # Create override directory
    mkdir -p "$root/etc/systemd/system/pigpiod.service.d"

    # CRITICAL: Proper ordering to avoid cycle with multi-user.target
    # and ensure pigpiod listens on IPv4 (not just IPv6)
    cat > "$root/etc/systemd/system/pigpiod.service.d/override.conf" << 'EOF'
[Unit]
# Delay start but don't create cycle with multi-user.target
# hyperpixel2r-init requires pigpiod, both wanted by multi-user.target
After=basic.target sysinit.target

[Service]
ExecStart=
# Wait 8 seconds for DPI overlay to stabilize before GPIO access
ExecStartPre=/bin/sleep 8
# No -l flag: must listen on IPv4 for Python pigpio library
ExecStart=/usr/bin/pigpiod
EOF

    log "pigpiod configured"
}

# ═══════════════════════════════════════════════════════════════════════════════
# HyperPixel LCD initialization service
# ═══════════════════════════════════════════════════════════════════════════════

install_hyperpixel_init() {
    log "Installing HyperPixel init..."

    local root="${ROOT_DIR:-}"

    # Service file
    cat > "$root/etc/systemd/system/hyperpixel2r-init.service" << 'EOF'
[Unit]
Description=HyperPixel 2.1 Round LCD Display Initialization
After=pigpiod.service
Requires=pigpiod.service
Before=secubox-fb-dashboard.service

[Service]
Type=oneshot
# Wait 3 seconds for pigpiod to be fully ready
ExecStartPre=/bin/sleep 3
ExecStart=/usr/local/sbin/hyperpixel2r-init
RemainAfterExit=yes
# CRITICAL: NO restart - one-time init only
# Restart causes IRQ conflicts with DPI overlay → kernel panic

[Install]
WantedBy=multi-user.target
EOF

    # Init script
    mkdir -p "$root/usr/local/sbin"
    cat > "$root/usr/local/sbin/hyperpixel2r-init" << 'INITSCRIPT'
#!/usr/bin/env python3
"""
HyperPixel 2.1 Round - ST7701S LCD Initialization
Sends SPI commands via pigpio to initialize the display controller.
"""

import sys
import time

try:
    import pigpio
except ImportError:
    print("ERROR: pigpio module not found. Install with: sudo apt install python3-pigpio")
    sys.exit(1)

# GPIO pins for software SPI
SPI_CLK = 11
SPI_MOSI = 10
SPI_CS = 18
BACKLIGHT = 19

# ST7701S initialization commands
INIT_COMMANDS = [
    (0xFF, [0x77, 0x01, 0x00, 0x00, 0x13]),
    (0xEF, [0x08]),
    (0xFF, [0x77, 0x01, 0x00, 0x00, 0x10]),
    (0xC0, [0x3B, 0x00]),
    (0xC1, [0x0D, 0x02]),
    (0xC2, [0x21, 0x08]),
    (0xCD, [0x18]),
    (0xB0, [0x00, 0x11, 0x18, 0x0E, 0x11, 0x06, 0x07, 0x08, 0x07, 0x22, 0x04, 0x12, 0x0F, 0xAA, 0x31, 0x18]),
    (0xB1, [0x00, 0x11, 0x19, 0x0E, 0x12, 0x07, 0x08, 0x08, 0x08, 0x22, 0x04, 0x11, 0x11, 0xA9, 0x32, 0x18]),
    (0xFF, [0x77, 0x01, 0x00, 0x00, 0x11]),
    (0xB0, [0x60]),
    (0xB1, [0x30]),
    (0xB2, [0x87]),
    (0xB3, [0x80]),
    (0xB5, [0x49]),
    (0xB7, [0x85]),
    (0xB8, [0x21]),
    (0xC1, [0x78]),
    (0xC2, [0x78]),
    (0xE0, [0x00, 0x1B, 0x02]),
    (0xE1, [0x08, 0xA0, 0x00, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x44, 0x44]),
    (0xE2, [0x11, 0x11, 0x44, 0x44, 0xED, 0xA0, 0x00, 0x00, 0xEC, 0xA0, 0x00, 0x00]),
    (0xE3, [0x00, 0x00, 0x11, 0x11]),
    (0xE4, [0x44, 0x44]),
    (0xE5, [0x0A, 0xE9, 0xD8, 0xA0, 0x0C, 0xEB, 0xD8, 0xA0, 0x0E, 0xED, 0xD8, 0xA0, 0x10, 0xEF, 0xD8, 0xA0]),
    (0xE6, [0x00, 0x00, 0x11, 0x11]),
    (0xE7, [0x44, 0x44]),
    (0xE8, [0x09, 0xE8, 0xD8, 0xA0, 0x0B, 0xEA, 0xD8, 0xA0, 0x0D, 0xEC, 0xD8, 0xA0, 0x0F, 0xEE, 0xD8, 0xA0]),
    (0xEB, [0x02, 0x00, 0xE4, 0xE4, 0x88, 0x00, 0x40]),
    (0xEC, [0x3C, 0x00]),
    (0xED, [0xAB, 0x89, 0x76, 0x54, 0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x20, 0x45, 0x67, 0x98, 0xBA]),
    (0xFF, [0x77, 0x01, 0x00, 0x00, 0x00]),
    (0x3A, [0x66]),
    (0x36, [0x00]),
    (0x11, []),
    (0x29, []),
]

def spi_write_byte(pi, byte):
    """Write a byte via software SPI."""
    for i in range(8):
        pi.write(SPI_MOSI, (byte >> (7 - i)) & 1)
        pi.write(SPI_CLK, 1)
        pi.write(SPI_CLK, 0)

def send_command(pi, cmd, data=None):
    """Send command and optional data to ST7701S."""
    pi.write(SPI_CS, 0)

    # Command byte (DC=0)
    spi_write_byte(pi, 0x00)
    spi_write_byte(pi, cmd)

    # Data bytes (DC=1)
    if data:
        for byte in data:
            spi_write_byte(pi, 0x01)
            spi_write_byte(pi, byte)

    pi.write(SPI_CS, 1)

def main():
    print("HyperPixel 2.1 Round - Initializing ST7701S LCD via pigpio...")

    try:
        pi = pigpio.pi()
        if not pi.connected:
            print("ERROR: Cannot connect to pigpiod.")
            return 1
    except Exception as e:
        print(f"ERROR: Cannot connect to pigpiod: {e}")
        return 1

    try:
        # Setup GPIO
        pi.set_mode(SPI_CLK, pigpio.OUTPUT)
        pi.set_mode(SPI_MOSI, pigpio.OUTPUT)
        pi.set_mode(SPI_CS, pigpio.OUTPUT)
        pi.set_mode(BACKLIGHT, pigpio.OUTPUT)

        # Initial state
        pi.write(SPI_CLK, 0)
        pi.write(SPI_CS, 1)
        pi.write(BACKLIGHT, 0)

        # Send init sequence
        for cmd, data in INIT_COMMANDS:
            send_command(pi, cmd, data)
            if cmd in (0x11, 0x29):
                time.sleep(0.12)

        # Enable backlight
        pi.write(BACKLIGHT, 1)

        print("ST7701S LCD initialized successfully!")
        return 0

    finally:
        pi.stop()

if __name__ == "__main__":
    sys.exit(main())
INITSCRIPT
    chmod +x "$root/usr/local/sbin/hyperpixel2r-init"

    log "HyperPixel init installed"
}

# ═══════════════════════════════════════════════════════════════════════════════
# USB Gadget service
# ═══════════════════════════════════════════════════════════════════════════════

install_gadget_service() {
    log "Installing USB gadget service..."

    local root="${ROOT_DIR:-}"

    # Service file
    cat > "$root/etc/systemd/system/secubox-eye-gadget.service" << 'EOF'
[Unit]
Description=SecuBox Eye Remote USB Gadget (Composite ECM+ACM+Storage)
After=systemd-modules-load.service sys-kernel-config.mount
Before=network.target
DefaultDependencies=no

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/sbin/modprobe dwc2
ExecStartPre=/sbin/modprobe libcomposite
# Wait for dwc2 driver to stabilize before gadget setup
ExecStartPre=/bin/sleep 8
ExecStart=/etc/secubox/eye-remote/gadget-setup.sh up
ExecStop=/etc/secubox/eye-remote/gadget-setup.sh down
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
EOF

    # Gadget setup script
    mkdir -p "$root/etc/secubox/eye-remote"
    cat > "$root/etc/secubox/eye-remote/gadget-setup.sh" << 'GADGETSCRIPT'
#!/bin/bash
set -euo pipefail

readonly VERSION="2.5.0"
readonly GADGET="/sys/kernel/config/usb_gadget/secubox"
readonly STORAGE_IMAGE="/var/lib/secubox/eye-remote/storage.img"
readonly STORAGE_SIZE_MB=2048
readonly STORAGE_ENABLED=true

log() { echo "[eye-gadget] $*"; logger -t eye-gadget "$*" 2>/dev/null || true; }

gadget_down() {
    [[ -d "$GADGET" ]] || return 0
    log "Stopping gadget..."
    echo "" > "$GADGET/UDC" 2>/dev/null || true
    rm -f $GADGET/configs/c.1/*.usb0 2>/dev/null || true
    rmdir $GADGET/configs/c.1/strings/0x409 2>/dev/null || true
    rmdir $GADGET/configs/c.1 2>/dev/null || true
    rmdir $GADGET/functions/ecm.usb0 2>/dev/null || true
    rmdir $GADGET/functions/acm.usb0 2>/dev/null || true
    rmdir $GADGET/functions/mass_storage.usb0/lun.0 2>/dev/null || true
    rmdir $GADGET/functions/mass_storage.usb0 2>/dev/null || true
    rmdir $GADGET/strings/0x409 2>/dev/null || true
    rmdir $GADGET 2>/dev/null || true
    log "Gadget stopped"
}

create_storage_image() {
    [[ -f "$STORAGE_IMAGE" ]] && return 0
    log "Creating storage image: $STORAGE_IMAGE (${STORAGE_SIZE_MB}MB)..."
    mkdir -p "$(dirname "$STORAGE_IMAGE")"
    dd if=/dev/zero of="$STORAGE_IMAGE" bs=1M count=0 seek="$STORAGE_SIZE_MB" 2>/dev/null
    mkfs.vfat -F 32 -n "SECUBOX" "$STORAGE_IMAGE" >/dev/null 2>&1 || true
    log "Storage image created"
}

gadget_up() {
    log "Starting USB gadget v${VERSION}..."
    gadget_down

    mkdir -p "$GADGET" && cd "$GADGET"

    # USB IDs
    echo 0x1d6b > idVendor
    echo 0x0104 > idProduct
    echo 0x0200 > bcdDevice
    echo 0xEF > bDeviceClass
    echo 0x02 > bDeviceSubClass
    echo 0x01 > bDeviceProtocol

    # Strings
    mkdir -p strings/0x409
    echo "CyberMind SecuBox" > strings/0x409/manufacturer
    echo "Eye Remote" > strings/0x409/product
    SERIAL=$(grep -oP 'Serial\s*:\s*\K[0-9a-f]+' /proc/cpuinfo 2>/dev/null || echo "0000001")
    echo "$SERIAL" > strings/0x409/serialnumber

    # Generate deterministic MAC from serial
    MAC_SUFFIX=$(echo "$SERIAL" | tail -c 7 | tr '[:lower:]' '[:upper:]')
    HOST_MAC="02:FB:00:00:${MAC_SUFFIX:0:2}:${MAC_SUFFIX:2:2}"
    DEV_MAC="02:FB:00:00:${MAC_SUFFIX:0:2}:$(printf '%02X' $((0x${MAC_SUFFIX:2:2} + 1)))"

    # ECM function (Linux/macOS network) - NO RNDIS to avoid duplicate interfaces
    mkdir -p functions/ecm.usb0
    echo "$HOST_MAC" > functions/ecm.usb0/host_addr
    echo "$DEV_MAC" > functions/ecm.usb0/dev_addr

    # ACM function (serial console)
    mkdir -p functions/acm.usb0

    # Mass Storage (optional)
    if [[ "$STORAGE_ENABLED" == "true" ]]; then
        create_storage_image
        mkdir -p functions/mass_storage.usb0/lun.0
        echo 1 > functions/mass_storage.usb0/lun.0/removable
        echo 0 > functions/mass_storage.usb0/lun.0/cdrom
        echo 0 > functions/mass_storage.usb0/lun.0/ro
        echo "$STORAGE_IMAGE" > functions/mass_storage.usb0/lun.0/file
    fi

    # Configuration
    mkdir -p configs/c.1/strings/0x409
    echo "SecuBox Eye Remote (ECM + ACM + Storage)" > configs/c.1/strings/0x409/configuration
    echo 500 > configs/c.1/MaxPower

    # Link functions
    ln -sf functions/ecm.usb0 configs/c.1/
    ln -sf functions/acm.usb0 configs/c.1/
    [[ "$STORAGE_ENABLED" == "true" ]] && ln -sf functions/mass_storage.usb0 configs/c.1/

    # Bind to UDC
    UDC=$(ls /sys/class/udc/ | head -1)
    [[ -n "$UDC" ]] || { log "ERROR: No UDC found"; return 1; }
    echo "$UDC" > UDC

    log "Gadget started on $UDC (MAC: $HOST_MAC)"
}

gadget_status() {
    if [[ -d "$GADGET" ]]; then
        local udc=$(cat "$GADGET/UDC" 2>/dev/null)
        [[ -n "$udc" ]] && echo '{"status":"running","udc":"'"$udc"'"}' || echo '{"status":"configured"}'
    else
        echo '{"status":"stopped"}'
    fi
}

case "${1:-}" in
    up|start)   gadget_up ;;
    down|stop)  gadget_down ;;
    status)     gadget_status ;;
    *)          echo "Usage: $0 {up|down|status}"; exit 1 ;;
esac
GADGETSCRIPT
    chmod +x "$root/etc/secubox/eye-remote/gadget-setup.sh"

    log "USB gadget service installed"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Serial console service
# ═══════════════════════════════════════════════════════════════════════════════

install_serial_console() {
    log "Installing serial console service..."

    local root="${ROOT_DIR:-}"

    cat > "$root/etc/systemd/system/secubox-serial-console.service" << 'EOF'
[Unit]
Description=SecuBox Console série USB (ttyGS0)
After=secubox-eye-gadget.service
Requires=secubox-eye-gadget.service
ConditionPathExists=/dev/ttyGS0

[Service]
Type=simple
ExecStart=/sbin/agetty -L 115200 ttyGS0 vt100
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    log "Serial console installed"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Enable services
# ═══════════════════════════════════════════════════════════════════════════════

enable_services() {
    log "Enabling services..."

    local root="${ROOT_DIR:-}"

    mkdir -p "$root/etc/systemd/system/multi-user.target.wants"

    # Enable services via symlinks (works on mounted SD card)
    ln -sf /etc/systemd/system/secubox-eye-gadget.service "$root/etc/systemd/system/multi-user.target.wants/"
    ln -sf /etc/systemd/system/hyperpixel2r-init.service "$root/etc/systemd/system/multi-user.target.wants/"
    ln -sf /etc/systemd/system/secubox-serial-console.service "$root/etc/systemd/system/multi-user.target.wants/"
    ln -sf /lib/systemd/system/pigpiod.service "$root/etc/systemd/system/multi-user.target.wants/"

    log "Services enabled"
}

# ═══════════════════════════════════════════════════════════════════════════════
# Main installation
# ═══════════════════════════════════════════════════════════════════════════════

main() {
    log "SecuBox Eye Remote Installer v${VERSION}"
    log "Mode: $MODE"

    configure_boot
    configure_system
    install_pigpiod_config
    install_hyperpixel_init
    install_gadget_service
    install_serial_console
    enable_services

    log "Installation complete!"
    log ""
    log "Next steps:"
    if [[ "$MODE" == "sdcard" ]]; then
        log "  1. Unmount SD card: sudo umount $BOOT_DIR $ROOT_DIR"
        log "  2. Insert SD card into Pi Zero W"
        log "  3. Connect to host via USB OTG port (not PWR port)"
        log "  4. Configure host: ip addr add 10.55.0.1/30 dev <interface>"
        log "  5. SSH: ssh pi@10.55.0.2"
    else
        log "  1. Reboot: sudo reboot"
        log "  2. Display should initialize automatically"
    fi
}

main "$@"
