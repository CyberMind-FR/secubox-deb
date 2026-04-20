#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# SecuBox Eye Remote — build-eye-remote-image.sh
# Creates a ready-to-flash SD image for RPi Zero W + HyperPixel 2.1 Round
#
# CyberMind — https://cybermind.fr
# Author: Gérald Kerma <gandalf@gk2.net>
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="1.8.0"
OUTPUT_DIR="${OUTPUT_DIR:-/tmp}"
OUTPUT_NAME="secubox-eye-remote-${VERSION}.img"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[build]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }
err()  { echo -e "${RED}[error]${NC} $*" >&2; exit 1; }

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# Default WiFi (user can override)
WIFI_SSID="${WIFI_SSID:-}"
WIFI_PSK="${WIFI_PSK:-}"
HOSTNAME="${HOSTNAME:-secubox-round}"
SSH_PUBKEY="${SSH_PUBKEY:-}"

# Source image
SOURCE_IMAGE=""

usage() {
    cat << EOF
SecuBox Eye Remote — Image Builder v${VERSION}

Usage: $0 [OPTIONS]

Options:
  -i, --image IMAGE       Source RPi OS Lite image (.img or .img.xz)
  -o, --output DIR        Output directory (default: /tmp)
  -s, --ssid SSID         WiFi SSID (optional)
  -p, --psk PSK           WiFi password (optional)
  -h, --hostname NAME     Hostname (default: secubox-round)
  -k, --pubkey FILE       SSH public key to install
  --help                  Show this help

Examples:
  # Build with WiFi pre-configured
  $0 -i raspios-lite.img.xz -s "MyWiFi" -p "password"

  # Build minimal (USB OTG only)
  $0 -i raspios-lite.img.xz

Output: ${OUTPUT_DIR}/${OUTPUT_NAME}
EOF
    exit 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# PARSE ARGUMENTS
# ═══════════════════════════════════════════════════════════════════════════════

while [[ $# -gt 0 ]]; do
    case "$1" in
        -i|--image) SOURCE_IMAGE="$2"; shift 2 ;;
        -o|--output) OUTPUT_DIR="$2"; shift 2 ;;
        -s|--ssid) WIFI_SSID="$2"; shift 2 ;;
        -p|--psk) WIFI_PSK="$2"; shift 2 ;;
        -h|--hostname) HOSTNAME="$2"; shift 2 ;;
        -k|--pubkey) SSH_PUBKEY="$2"; shift 2 ;;
        --help) usage ;;
        *) err "Unknown option: $1" ;;
    esac
done

[[ -z "$SOURCE_IMAGE" ]] && err "Source image required. Use -i option."
[[ ! -f "$SOURCE_IMAGE" ]] && err "Image not found: $SOURCE_IMAGE"

# ═══════════════════════════════════════════════════════════════════════════════
# BUILD IMAGE
# ═══════════════════════════════════════════════════════════════════════════════

OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_NAME}"
log "Building SecuBox Eye Remote image v${VERSION}"
log "Source: $SOURCE_IMAGE"
log "Output: $OUTPUT_PATH"

# Decompress if needed
if [[ "$SOURCE_IMAGE" == *.xz ]]; then
    log "Decompressing image..."
    TEMP_IMG="${OUTPUT_DIR}/eye-remote-temp.img"
    xzcat "$SOURCE_IMAGE" > "$TEMP_IMG"
    SOURCE_IMAGE="$TEMP_IMG"
fi

# Copy to output
log "Creating output image..."
cp "$SOURCE_IMAGE" "$OUTPUT_PATH"

# Setup loop device
log "Setting up loop device..."
LOOP_DEV=$(sudo losetup -fP --show "$OUTPUT_PATH")
trap "sudo losetup -d $LOOP_DEV 2>/dev/null || true" EXIT

# Mount partitions
BOOT_MNT=$(mktemp -d)
ROOT_MNT=$(mktemp -d)
trap "sudo umount $BOOT_MNT $ROOT_MNT 2>/dev/null || true; sudo losetup -d $LOOP_DEV 2>/dev/null || true; rm -rf $BOOT_MNT $ROOT_MNT" EXIT

log "Mounting partitions..."
sudo mount "${LOOP_DEV}p1" "$BOOT_MNT"
sudo mount "${LOOP_DEV}p2" "$ROOT_MNT"

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURE BOOT PARTITION
# ═══════════════════════════════════════════════════════════════════════════════

log "Configuring boot partition..."

# Enable SSH
sudo touch "$BOOT_MNT/ssh"

# Create userconf (pi:raspberry)
echo 'pi:$6$k5SVZ0uuYIi5gexv$2hLzZeHHwXdRLXpLP1M3dP8PTKRP0z/ejvFmrXeQPrl7NdIdcJGwY/gbr8vwAV6CXYri0fL.1SkRNZH/WcFyv1' | \
    sudo tee "$BOOT_MNT/userconf" > /dev/null

# Configure WiFi if provided
if [[ -n "$WIFI_SSID" && -n "$WIFI_PSK" ]]; then
    log "Configuring WiFi: $WIFI_SSID"
    sudo tee "$BOOT_MNT/wpa_supplicant.conf" > /dev/null << EOF
country=FR
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1

network={
    ssid="$WIFI_SSID"
    psk="$WIFI_PSK"
    key_mgmt=WPA-PSK
    priority=1
}
EOF
fi

# HyperPixel + USB OTG config
log "Configuring HyperPixel + USB OTG..."

# Verify KMS overlay exists in base image (preferred, no init script needed)
OVERLAYS_DIR="$BOOT_MNT/overlays"
[[ ! -d "$OVERLAYS_DIR" ]] && OVERLAYS_DIR="$BOOT_MNT/firmware/overlays"
if [[ -f "$OVERLAYS_DIR/vc4-kms-dpi-hyperpixel2r.dtbo" ]]; then
    log "Using KMS overlay vc4-kms-dpi-hyperpixel2r (built-in)"
    HP_OVERLAY="vc4-kms-dpi-hyperpixel2r"
else
    log "Slipstreaming legacy hyperpixel2r.dtbo overlay..."
    sudo cp "$SCRIPT_DIR/hyperpixel2r.dtbo" "$OVERLAYS_DIR/"
    sudo cp "$SCRIPT_DIR/hyperpixel2r-init" "$ROOT_MNT/usr/local/bin/" 2>/dev/null || true
    HP_OVERLAY="hyperpixel2r"
fi

# Remove any existing dwc2 host mode (base image issue)
sudo sed -i 's/dtoverlay=dwc2,dr_mode=host/#REMOVED: dtoverlay=dwc2,dr_mode=host/' "$BOOT_MNT/config.txt"

sudo tee -a "$BOOT_MNT/config.txt" > /dev/null << EOF

# === SecuBox Eye Remote v1.8.0 ===
# HyperPixel 2.1 Round (KMS overlay - no init script needed)
dtoverlay=$HP_OVERLAY
dtparam=i2c_arm=on
dtparam=spi=on
display_auto_detect=0

# USB OTG Gadget (peripheral mode)
dtoverlay=dwc2
EOF

# cmdline.txt: load modules
CMDLINE=$(cat "$BOOT_MNT/cmdline.txt")
if [[ ! "$CMDLINE" == *"modules-load"* ]]; then
    sudo sed -i 's/rootwait/rootwait modules-load=dwc2,libcomposite/' "$BOOT_MNT/cmdline.txt"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURE ROOT FILESYSTEM
# ═══════════════════════════════════════════════════════════════════════════════

log "Configuring root filesystem..."

# Hostname
echo "$HOSTNAME" | sudo tee "$ROOT_MNT/etc/hostname" > /dev/null
sudo sed -i "s/127.0.1.1.*/127.0.1.1\t$HOSTNAME/" "$ROOT_MNT/etc/hosts"

# Modules
sudo tee -a "$ROOT_MNT/etc/modules" > /dev/null << 'EOF'
dwc2
libcomposite
usb_f_ecm
usb_f_acm
usb_f_mass_storage
usb_f_hid
EOF

# Modprobe config
sudo mkdir -p "$ROOT_MNT/etc/modprobe.d"
echo "options dwc2 dr_mode=peripheral" | sudo tee "$ROOT_MNT/etc/modprobe.d/secubox-otg.conf" > /dev/null

# Copy gadget scripts
log "Installing Eye Remote scripts..."
sudo mkdir -p "$ROOT_MNT/usr/local/sbin"
sudo cp "$SCRIPT_DIR/secubox-otg-gadget.sh" "$ROOT_MNT/usr/local/sbin/"
sudo cp "$SCRIPT_DIR/secubox-hid-keyboard.sh" "$ROOT_MNT/usr/local/sbin/"
sudo chmod +x "$ROOT_MNT/usr/local/sbin/secubox-"*.sh

# Copy systemd services
sudo cp "$SCRIPT_DIR/secubox-otg-gadget.service" "$ROOT_MNT/etc/systemd/system/"
sudo cp "$SCRIPT_DIR/secubox-serial-console.service" "$ROOT_MNT/etc/systemd/system/"
sudo cp "$SCRIPT_DIR/secubox-remote-ui.service" "$ROOT_MNT/etc/systemd/system/"

# Enable services
sudo mkdir -p "$ROOT_MNT/etc/systemd/system/multi-user.target.wants"
sudo ln -sf /etc/systemd/system/secubox-otg-gadget.service \
    "$ROOT_MNT/etc/systemd/system/multi-user.target.wants/"
sudo ln -sf /etc/systemd/system/secubox-serial-console.service \
    "$ROOT_MNT/etc/systemd/system/multi-user.target.wants/"

# Network config for usb0
sudo mkdir -p "$ROOT_MNT/etc/network/interfaces.d"
sudo tee "$ROOT_MNT/etc/network/interfaces.d/usb0" > /dev/null << 'EOF'
allow-hotplug usb0
iface usb0 inet static
    address 10.55.0.2
    netmask 255.255.255.252
    gateway 10.55.0.1
EOF

# Create gadget data directory
sudo mkdir -p "$ROOT_MNT/var/lib/secubox-gadget"
sudo truncate -s 512M "$ROOT_MNT/var/lib/secubox-gadget/debug.img"

# Copy dashboard
log "Installing Eye Remote dashboard..."
sudo mkdir -p "$ROOT_MNT/var/www/secubox-round"
sudo cp "$SCRIPT_DIR/index.html" "$ROOT_MNT/var/www/secubox-round/"

# SSH key if provided
if [[ -n "$SSH_PUBKEY" && -f "$SSH_PUBKEY" ]]; then
    log "Installing SSH key..."
    sudo mkdir -p "$ROOT_MNT/home/pi/.ssh"
    sudo cp "$SSH_PUBKEY" "$ROOT_MNT/home/pi/.ssh/authorized_keys"
    sudo chmod 700 "$ROOT_MNT/home/pi/.ssh"
    sudo chmod 600 "$ROOT_MNT/home/pi/.ssh/authorized_keys"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# FINALIZE
# ═══════════════════════════════════════════════════════════════════════════════

log "Syncing..."
sync

log ""
log "═══════════════════════════════════════════════════════════════"
log "SecuBox Eye Remote image built successfully!"
log "═══════════════════════════════════════════════════════════════"
log ""
log "Output: $OUTPUT_PATH"
log "Size:   $(du -h "$OUTPUT_PATH" | cut -f1)"
log ""
log "Flash to SD card:"
log "  sudo dd if=$OUTPUT_PATH of=/dev/sdX bs=4M status=progress"
log ""
log "Or use Raspberry Pi Imager / balenaEtcher"
log ""
