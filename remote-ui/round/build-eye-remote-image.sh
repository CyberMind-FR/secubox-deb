#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# SecuBox Eye Remote — build-eye-remote-image.sh
# Creates a ready-to-flash SD image for RPi Zero W + HyperPixel 2.1 Round
#
# OFFLINE MODE: All packages pre-installed via QEMU chroot
# No internet required at first boot!
#
# CyberMind — https://cybermind.fr
# Author: Gérald Kerma <gandalf@gk2.net>
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="2.0.0"
OUTPUT_DIR="${OUTPUT_DIR:-/tmp}"
OUTPUT_NAME="secubox-eye-remote-${VERSION}.img"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${GREEN}[build]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }
err()  { echo -e "${RED}[error]${NC} $*" >&2; exit 1; }
info() { echo -e "${BLUE}[info]${NC} $*"; }

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

# Image size increase (MB) for pre-installed packages
IMAGE_EXPAND_MB=1024

# Build mode: "browser" (Chromium kiosk) or "framebuffer" (Python/PIL direct)
BUILD_MODE="framebuffer"  # Default: lightweight framebuffer mode

# Packages for framebuffer mode (lightweight, ~50MB)
PACKAGES_FRAMEBUFFER=(
    # Python for dashboard rendering
    python3-pil
    python3-pip
    python3-pigpio
    python3-aiohttp
    pigpio
    # Utilities
    i2c-tools
    # Fonts
    fonts-dejavu-core
)

# Additional packages for browser mode (~200MB more)
PACKAGES_BROWSER=(
    chromium-browser
    xserver-xorg
    xserver-xorg-video-fbdev
    xinit
    lightdm
    openbox
    x11-xserver-utils
    unclutter
    nginx
    git
)

# Active package list (set after parsing args)
PACKAGES=()

usage() {
    cat << EOF
SecuBox Eye Remote — Image Builder v${VERSION}

OFFLINE MODE: All packages pre-installed via QEMU chroot.
No internet required at first boot!

Usage: $0 [OPTIONS]

Options:
  -i, --image IMAGE       Source RPi OS Lite image (.img or .img.xz)
  -o, --output DIR        Output directory (default: /tmp)
  -s, --ssid SSID         WiFi SSID (optional)
  -p, --psk PSK           WiFi password (optional)
  -h, --hostname NAME     Hostname (default: secubox-round)
  -k, --pubkey FILE       SSH public key to install
  --browser               Use Chromium kiosk mode (~250MB more)
  --framebuffer           Use Python/PIL framebuffer (default, lightweight)
  --help                  Show this help

Build Modes:
  framebuffer (default)   Python renders directly to /dev/fb0
                          Lightweight: ~50MB packages, fast boot
                          No X11 or browser needed

  browser                 Chromium kiosk with HTML dashboard
                          Heavy: ~250MB packages, slower boot
                          Full web capabilities

Requirements:
  - qemu-user-static (for ARM emulation)
  - binfmt-support
  - sudo privileges

Examples:
  # Lightweight framebuffer mode (recommended)
  sudo $0 -i raspios-lite.img.xz

  # With WiFi pre-configured
  sudo $0 -i raspios-lite.img.xz -s "MyWiFi" -p "password"

  # Browser kiosk mode
  sudo $0 -i raspios-lite.img.xz --browser

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
        --browser) BUILD_MODE="browser"; shift ;;
        --framebuffer) BUILD_MODE="framebuffer"; shift ;;
        --help) usage ;;
        *) err "Unknown option: $1" ;;
    esac
done

[[ -z "$SOURCE_IMAGE" ]] && err "Source image required. Use -i option."
[[ ! -f "$SOURCE_IMAGE" ]] && err "Image not found: $SOURCE_IMAGE"

# Set package list based on build mode
if [[ "$BUILD_MODE" == "browser" ]]; then
    log "Build mode: BROWSER (Chromium kiosk)"
    PACKAGES=("${PACKAGES_FRAMEBUFFER[@]}" "${PACKAGES_BROWSER[@]}")
    IMAGE_EXPAND_MB=1536  # More space for browser
else
    log "Build mode: FRAMEBUFFER (Python/PIL direct)"
    PACKAGES=("${PACKAGES_FRAMEBUFFER[@]}")
    IMAGE_EXPAND_MB=768   # Space for PIL and dependencies
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PREREQUISITES CHECK
# ═══════════════════════════════════════════════════════════════════════════════

if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root (sudo)"
fi

# Check for QEMU
if ! command -v qemu-arm-static &>/dev/null; then
    err "qemu-user-static required. Install with: apt install qemu-user-static binfmt-support"
fi

# Check binfmt is registered
if [[ ! -f /proc/sys/fs/binfmt_misc/qemu-arm ]]; then
    warn "ARM binfmt not registered. Attempting to register..."
    update-binfmts --enable qemu-arm 2>/dev/null || true
    if [[ ! -f /proc/sys/fs/binfmt_misc/qemu-arm ]]; then
        err "Failed to register ARM binfmt. Run: systemctl restart binfmt-support"
    fi
fi

log "Prerequisites OK (QEMU ARM emulation available)"

# ═══════════════════════════════════════════════════════════════════════════════
# BUILD IMAGE
# ═══════════════════════════════════════════════════════════════════════════════

OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_NAME}"
log "Building SecuBox Eye Remote image v${VERSION} (OFFLINE MODE)"
log "Source: $SOURCE_IMAGE"
log "Output: $OUTPUT_PATH"

# Decompress if needed
WORK_IMG="${OUTPUT_DIR}/eye-remote-work.img"
if [[ "$SOURCE_IMAGE" == *.xz ]]; then
    log "Decompressing image..."
    xzcat "$SOURCE_IMAGE" > "$WORK_IMG"
else
    cp "$SOURCE_IMAGE" "$WORK_IMG"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# EXPAND IMAGE (for pre-installed packages)
# ═══════════════════════════════════════════════════════════════════════════════

log "Expanding image by ${IMAGE_EXPAND_MB}MB for packages..."
dd if=/dev/zero bs=1M count=${IMAGE_EXPAND_MB} >> "$WORK_IMG" 2>/dev/null

# Expand root partition
PART_INFO=$(parted -s "$WORK_IMG" unit s print 2>/dev/null | grep "^ 2" || true)
if [[ -n "$PART_INFO" ]]; then
    # Resize partition 2 to fill space
    parted -s "$WORK_IMG" resizepart 2 100%
    log "Root partition expanded"
fi

# Setup loop device
log "Setting up loop device..."
LOOP_DEV=$(losetup -fP --show "$WORK_IMG")

cleanup() {
    log "Cleaning up..."
    # Unmount in reverse order
    umount "$ROOT_MNT/boot/firmware" 2>/dev/null || true
    umount "$ROOT_MNT/dev/pts" 2>/dev/null || true
    umount "$ROOT_MNT/dev" 2>/dev/null || true
    umount "$ROOT_MNT/proc" 2>/dev/null || true
    umount "$ROOT_MNT/sys" 2>/dev/null || true
    umount "$ROOT_MNT" 2>/dev/null || true
    umount "$BOOT_MNT" 2>/dev/null || true
    losetup -d "$LOOP_DEV" 2>/dev/null || true
    rm -rf "$BOOT_MNT" "$ROOT_MNT" 2>/dev/null || true
}
trap cleanup EXIT

# Resize filesystem to fill partition
log "Resizing filesystem..."
e2fsck -f -y "${LOOP_DEV}p2" 2>/dev/null || true
resize2fs "${LOOP_DEV}p2"

# Mount partitions
BOOT_MNT=$(mktemp -d)
ROOT_MNT=$(mktemp -d)

log "Mounting partitions..."
mount "${LOOP_DEV}p2" "$ROOT_MNT"
mount "${LOOP_DEV}p1" "$BOOT_MNT"

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURE BOOT PARTITION
# ═══════════════════════════════════════════════════════════════════════════════

log "Configuring boot partition..."

# Enable SSH
touch "$BOOT_MNT/ssh"

# Create userconf (pi:raspberry)
echo 'pi:$6$k5SVZ0uuYIi5gexv$2hLzZeHHwXdRLXpLP1M3dP8PTKRP0z/ejvFmrXeQPrl7NdIdcJGwY/gbr8vwAV6CXYri0fL.1SkRNZH/WcFyv1' > "$BOOT_MNT/userconf"

# Configure WiFi if provided
if [[ -n "$WIFI_SSID" && -n "$WIFI_PSK" ]]; then
    log "Configuring WiFi: $WIFI_SSID"
    cat > "$BOOT_MNT/wpa_supplicant.conf" << EOF
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

# ═══════════════════════════════════════════════════════════════════════════════
# HYPERPIXEL CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

log "Configuring HyperPixel 2.1 Round..."

# Detect overlays directory
OVERLAYS_DIR="$BOOT_MNT/overlays"
[[ ! -d "$OVERLAYS_DIR" ]] && OVERLAYS_DIR="$BOOT_MNT/firmware/overlays"

# IMPORTANT: Pi Zero W does NOT support KMS properly!
# Always use legacy DPI mode with hyperpixel2r overlay + ST7701S init script
USE_KMS_OVERLAY=false
log "Using LEGACY DPI mode (Pi Zero W does not support KMS)"

# Copy our working hyperpixel2r.dtbo overlay
if [[ -f "$SCRIPT_DIR/hyperpixel/hyperpixel2r.dtbo" ]]; then
    log "Installing hyperpixel2r.dtbo overlay..."
    cp "$SCRIPT_DIR/hyperpixel/hyperpixel2r.dtbo" "$OVERLAYS_DIR/"
    HP_OVERLAY="hyperpixel2r"
else
    err "Missing hyperpixel2r.dtbo in $SCRIPT_DIR/hyperpixel/"
fi

# Install HyperPixel init script (REQUIRED for ST7701S LCD)
# Uses pigpio to bit-bang SPI commands to initialize the display controller
if [[ -f "$SCRIPT_DIR/hyperpixel/hyperpixel2r-init" ]]; then
    log "Installing hyperpixel2r-init script (pigpio-based)..."
    mkdir -p "$ROOT_MNT/usr/bin"
    cp "$SCRIPT_DIR/hyperpixel/hyperpixel2r-init" "$ROOT_MNT/usr/bin/"
    chmod +x "$ROOT_MNT/usr/bin/hyperpixel2r-init"

    # Copy service file (requires pigpiod)
    cp "$SCRIPT_DIR/hyperpixel/hyperpixel2r-init.service" "$ROOT_MNT/etc/systemd/system/"

    # Enable services (pigpiod + hyperpixel2r-init)
    mkdir -p "$ROOT_MNT/etc/systemd/system/multi-user.target.wants"
    ln -sf /lib/systemd/system/pigpiod.service \
        "$ROOT_MNT/etc/systemd/system/multi-user.target.wants/pigpiod.service"
    ln -sf /etc/systemd/system/hyperpixel2r-init.service \
        "$ROOT_MNT/etc/systemd/system/multi-user.target.wants/hyperpixel2r-init.service"
    log "Enabled pigpiod and hyperpixel2r-init services"
else
    err "Missing hyperpixel2r-init script in $SCRIPT_DIR/hyperpixel/"
fi

# Clean existing config
sed -i 's/dtoverlay=dwc2,dr_mode=host/#REMOVED: dtoverlay=dwc2,dr_mode=host/' "$BOOT_MNT/config.txt"
sed -i '/hyperpixel/d' "$BOOT_MNT/config.txt" 2>/dev/null || true
sed -i '/HyperPixel/d' "$BOOT_MNT/config.txt" 2>/dev/null || true

# Handle vc4-kms-v3d based on overlay type
if [[ "$USE_KMS_OVERLAY" == "true" ]]; then
    sed -i 's/^#dtoverlay=vc4-kms-v3d.*/dtoverlay=vc4-kms-v3d/' "$BOOT_MNT/config.txt" 2>/dev/null || true
else
    sed -i 's/^dtoverlay=vc4-kms-v3d/#dtoverlay=vc4-kms-v3d  # DISABLED - HyperPixel conflict/' "$BOOT_MNT/config.txt" 2>/dev/null || true
    sed -i 's/^dtoverlay=vc4-fkms-v3d/#dtoverlay=vc4-fkms-v3d  # DISABLED - HyperPixel conflict/' "$BOOT_MNT/config.txt" 2>/dev/null || true
fi
sed -i 's/^display_auto_detect=1/display_auto_detect=0/' "$BOOT_MNT/config.txt" 2>/dev/null || true

# Write HyperPixel config
cat >> "$BOOT_MNT/config.txt" << EOF

# === SecuBox Eye Remote v${VERSION} (OFFLINE) ===
display_auto_detect=0
camera_auto_detect=0
enable_tvout=0
hdmi_blanking=2
gpu_mem=128

EOF

if [[ "$USE_KMS_OVERLAY" == "true" ]]; then
    cat >> "$BOOT_MNT/config.txt" << KMSCONFIG
# KMS graphics driver
dtoverlay=vc4-kms-v3d

# HyperPixel 2.1 Round 480x480 - KMS overlay
dtoverlay=${HP_OVERLAY}

# I2C and SPI for touch
dtparam=i2c_arm=on
dtparam=spi=on

# USB OTG Gadget
dtoverlay=dwc2
KMSCONFIG
else
    cat >> "$BOOT_MNT/config.txt" << NONKMSCONFIG
# HyperPixel 2.1 Round 480x480 - non-KMS overlay (DPI mode)
# FIX: Use hyperpixel2r (not hyperpixel4), no disable-i2c flag
dtoverlay=${HP_OVERLAY}

# DPI configuration (required for ST7701S LCD)
enable_dpi_lcd=1
display_default_lcd=1
dpi_group=2
dpi_mode=87
dpi_output_format=0x7f216
dpi_timings=480 0 10 16 55 480 0 15 60 15 0 0 0 60 0 19200000 6
framebuffer_width=480
framebuffer_height=480
display_rotate=0

# I2C and SPI for touch
dtparam=i2c_arm=on
dtparam=spi=on

# USB OTG Gadget
dtoverlay=dwc2
NONKMSCONFIG
fi

# cmdline.txt: load modules
CMDLINE=$(cat "$BOOT_MNT/cmdline.txt")
if [[ ! "$CMDLINE" == *"modules-load"* ]]; then
    sed -i 's/rootwait/rootwait modules-load=dwc2,libcomposite/' "$BOOT_MNT/cmdline.txt"
fi

log "config.txt configured: overlay=$HP_OVERLAY KMS=$USE_KMS_OVERLAY"

# ═══════════════════════════════════════════════════════════════════════════════
# SETUP QEMU CHROOT FOR PACKAGE INSTALLATION
# ═══════════════════════════════════════════════════════════════════════════════

log "Setting up QEMU chroot for ARM emulation..."

# Copy QEMU binary
cp /usr/bin/qemu-arm-static "$ROOT_MNT/usr/bin/"

# Mount special filesystems for chroot
mount --bind /dev "$ROOT_MNT/dev"
mount --bind /dev/pts "$ROOT_MNT/dev/pts"
mount -t proc proc "$ROOT_MNT/proc"
mount -t sysfs sys "$ROOT_MNT/sys"

# Mount boot inside chroot (for Bookworm)
if [[ -d "$ROOT_MNT/boot/firmware" ]]; then
    mount --bind "$BOOT_MNT" "$ROOT_MNT/boot/firmware"
fi

# Prevent services from starting during install
cat > "$ROOT_MNT/usr/sbin/policy-rc.d" << 'POLICY'
#!/bin/sh
exit 101
POLICY
chmod +x "$ROOT_MNT/usr/sbin/policy-rc.d"

# Setup DNS for network access in chroot
cp /etc/resolv.conf "$ROOT_MNT/etc/resolv.conf"
log "DNS configured for chroot"

# ═══════════════════════════════════════════════════════════════════════════════
# INSTALL PACKAGES VIA CHROOT
# ═══════════════════════════════════════════════════════════════════════════════

log "Installing packages via QEMU chroot (this takes a while)..."
info "Packages: ${PACKAGES[*]}"

# Create package list file (dynamically based on BUILD_MODE)
printf "%s\n" "${PACKAGES[@]}" > "$ROOT_MNT/tmp/package-list.txt"

# Create install script
cat > "$ROOT_MNT/tmp/install-packages.sh" << 'INSTALLSCRIPT'
#!/bin/bash
set -e

export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C

echo "=== Updating APT ==="
apt-get update -qq

echo "=== Installing packages ==="
# Read packages from file and install with --no-install-recommends
xargs -a /tmp/package-list.txt apt-get install -y -qq --no-install-recommends

echo "=== Enabling pigpiod ==="
systemctl enable pigpiod || true

echo "=== Cleaning APT cache ==="
apt-get clean
rm -rf /var/lib/apt/lists/*
rm -f /tmp/package-list.txt

echo "=== Package installation complete ==="
INSTALLSCRIPT
chmod +x "$ROOT_MNT/tmp/install-packages.sh"

# Run install in chroot
chroot "$ROOT_MNT" /tmp/install-packages.sh

# Remove policy
rm -f "$ROOT_MNT/usr/sbin/policy-rc.d"

log "Packages installed successfully"

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURE ROOT FILESYSTEM
# ═══════════════════════════════════════════════════════════════════════════════

log "Configuring root filesystem..."

# Hostname
echo "$HOSTNAME" > "$ROOT_MNT/etc/hostname"
sed -i "s/127.0.1.1.*/127.0.1.1\t$HOSTNAME/" "$ROOT_MNT/etc/hosts"

# Modules for USB OTG
cat >> "$ROOT_MNT/etc/modules" << 'EOF'
dwc2
libcomposite
usb_f_ecm
usb_f_acm
usb_f_mass_storage
usb_f_hid
EOF

# Modprobe config
mkdir -p "$ROOT_MNT/etc/modprobe.d"
echo "options dwc2 dr_mode=peripheral" > "$ROOT_MNT/etc/modprobe.d/secubox-otg.conf"

# Copy gadget scripts
log "Installing Eye Remote scripts..."
mkdir -p "$ROOT_MNT/usr/local/sbin"
cp "$SCRIPT_DIR/secubox-otg-gadget.sh" "$ROOT_MNT/usr/local/sbin/"
cp "$SCRIPT_DIR/secubox-hid-keyboard.sh" "$ROOT_MNT/usr/local/sbin/"
chmod +x "$ROOT_MNT/usr/local/sbin/secubox-"*.sh

# Copy framebuffer dashboard (Pi Zero W has no NEON, can't run Chromium)
log "Installing framebuffer dashboard..."
mkdir -p "$ROOT_MNT/usr/local/bin"
cp "$SCRIPT_DIR/fb_dashboard.py" "$ROOT_MNT/usr/local/bin/"
chmod +x "$ROOT_MNT/usr/local/bin/fb_dashboard.py"

# Install Eye Agent (daemon + config + systemd service)
if [[ -f "$SCRIPT_DIR/secubox-eye-agent.service" && -f "$SCRIPT_DIR/config.toml.example" ]]; then
    log "Installing Eye Agent..."
    mkdir -p "$ROOT_MNT/usr/lib/secubox-eye/agent"
    mkdir -p "$ROOT_MNT/etc/secubox-eye"

    # Copy agent modules (quote glob properly)
    cp -r "$SCRIPT_DIR/agent"/*.py "$ROOT_MNT/usr/lib/secubox-eye/agent/" || err "Failed to copy agent modules"

    # Copy example config with secure permissions
    cp "$SCRIPT_DIR/config.toml.example" "$ROOT_MNT/etc/secubox-eye/config.toml"
    chmod 600 "$ROOT_MNT/etc/secubox-eye/config.toml"

    # Install agent service
    cp "$SCRIPT_DIR/secubox-eye-agent.service" "$ROOT_MNT/etc/systemd/system/"

    # Enable agent service via symlink (atomic, no chroot needed)
    mkdir -p "$ROOT_MNT/etc/systemd/system/multi-user.target.wants"
    ln -sf /etc/systemd/system/secubox-eye-agent.service \
        "$ROOT_MNT/etc/systemd/system/multi-user.target.wants/"
else
    warn "Eye Agent files not found, skipping installation"
fi

# Copy systemd services
cp "$SCRIPT_DIR/secubox-otg-gadget.service" "$ROOT_MNT/etc/systemd/system/"
cp "$SCRIPT_DIR/secubox-serial-console.service" "$ROOT_MNT/etc/systemd/system/"
cp "$SCRIPT_DIR/secubox-fb-dashboard.service" "$ROOT_MNT/etc/systemd/system/"

# Enable services
mkdir -p "$ROOT_MNT/etc/systemd/system/multi-user.target.wants"
ln -sf /etc/systemd/system/secubox-otg-gadget.service \
    "$ROOT_MNT/etc/systemd/system/multi-user.target.wants/"
ln -sf /etc/systemd/system/secubox-serial-console.service \
    "$ROOT_MNT/etc/systemd/system/multi-user.target.wants/"
ln -sf /etc/systemd/system/secubox-fb-dashboard.service \
    "$ROOT_MNT/etc/systemd/system/multi-user.target.wants/"

# Network config for usb0
mkdir -p "$ROOT_MNT/etc/network/interfaces.d"
cat > "$ROOT_MNT/etc/network/interfaces.d/usb0" << 'EOF'
allow-hotplug usb0
iface usb0 inet static
    address 10.55.0.2
    netmask 255.255.255.252
    gateway 10.55.0.1
EOF

# usb0-up.sh script (NetworkManager bypass)
mkdir -p "$ROOT_MNT/usr/local/bin"
cat > "$ROOT_MNT/usr/local/bin/usb0-up.sh" << 'USB0UP'
#!/bin/bash
LOG=/var/log/usb0-up.log
exec >> "$LOG" 2>&1
echo "=== usb0-up.sh started $(date) ==="
sleep 5
for i in {1..30}; do
    if ip link show usb0 &>/dev/null; then
        ip addr add 10.55.0.2/30 dev usb0 2>&1 || true
        ip link set usb0 up 2>&1
        ip route add default via 10.55.0.1 dev usb0 2>&1 || true
        logger "SecuBox OTG: usb0 configured 10.55.0.2/30"
        exit 0
    fi
    sleep 2
done
exit 1
USB0UP
chmod +x "$ROOT_MNT/usr/local/bin/usb0-up.sh"

cat > "$ROOT_MNT/etc/systemd/system/usb0-up.service" << 'USB0SVC'
[Unit]
Description=SecuBox USB Gadget Network Setup
After=systemd-modules-load.service secubox-otg-gadget.service
Wants=secubox-otg-gadget.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/usb0-up.sh
RemainAfterExit=yes
TimeoutStartSec=90

[Install]
WantedBy=multi-user.target
USB0SVC
ln -sf /etc/systemd/system/usb0-up.service \
    "$ROOT_MNT/etc/systemd/system/multi-user.target.wants/usb0-up.service"

# Create gadget data directory
mkdir -p "$ROOT_MNT/var/lib/secubox-gadget"
truncate -s 512M "$ROOT_MNT/var/lib/secubox-gadget/debug.img"

# ═══════════════════════════════════════════════════════════════════════════════
# CREATE SECUBOX USER AND CONFIGURE KIOSK
# ═══════════════════════════════════════════════════════════════════════════════

log "Creating secubox user and configuring kiosk..."

# Create user via chroot
cat > "$ROOT_MNT/tmp/setup-user.sh" << 'USERSCRIPT'
#!/bin/bash
set -e

# Create secubox user if not exists
if ! id secubox &>/dev/null; then
    useradd -m -s /bin/bash secubox
    echo "secubox:secubox2026" | chpasswd
fi

# Add to groups
usermod -aG video,input,gpio,i2c,spi,audio secubox 2>/dev/null || true

# Enable lightdm and nginx
systemctl enable lightdm 2>/dev/null || true
systemctl enable nginx 2>/dev/null || true
USERSCRIPT
chmod +x "$ROOT_MNT/tmp/setup-user.sh"
chroot "$ROOT_MNT" /tmp/setup-user.sh

# LightDM autologin
mkdir -p "$ROOT_MNT/etc/lightdm/lightdm.conf.d"
cat > "$ROOT_MNT/etc/lightdm/lightdm.conf.d/50-autologin.conf" << 'LIGHTDM'
[Seat:*]
autologin-user=secubox
autologin-user-timeout=0
user-session=openbox
LIGHTDM

# Openbox config
mkdir -p "$ROOT_MNT/home/secubox/.config/openbox"
cat > "$ROOT_MNT/home/secubox/.config/openbox/autostart" << 'AUTOSTART'
# Disable screensaver
xset s off &
xset -dpms &
xset s noblank &

# Hide cursor
unclutter -idle 0.1 -root &

# Wait for nginx
sleep 3

# Launch Chromium in kiosk mode
chromium-browser \
    --kiosk \
    --noerrdialogs \
    --disable-infobars \
    --disable-session-crashed-bubble \
    --disable-restore-session-state \
    --disable-translate \
    --no-first-run \
    --start-fullscreen \
    --window-size=480,480 \
    --window-position=0,0 \
    --disable-gpu \
    --use-gl=egl \
    http://localhost:8080
AUTOSTART

# xinitrc
cat > "$ROOT_MNT/home/secubox/.xinitrc" << 'XINITRC'
#!/bin/bash
xset s off
xset -dpms
xset s noblank
unclutter -idle 0.1 -root &
exec openbox-session
XINITRC
chmod +x "$ROOT_MNT/home/secubox/.xinitrc"

# Fix ownership
chroot "$ROOT_MNT" chown -R secubox:secubox /home/secubox

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURE NGINX (browser mode only)
# ═══════════════════════════════════════════════════════════════════════════════

if [[ "$BUILD_MODE" == "browser" ]]; then
    log "Configuring nginx..."

    cat > "$ROOT_MNT/etc/nginx/sites-available/secubox-round" << 'NGINX'
server {
    listen 8080 default_server;
    server_name _;

    root /var/www/secubox-round;
    index index.html;

    # Proxy to SecuBox API
    location /api/ {
        proxy_pass http://10.55.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_connect_timeout 5s;
        proxy_read_timeout 30s;
    }

    location / {
        try_files $uri $uri/ =404;
    }
}
NGINX

    # Enable nginx site
    ln -sf /etc/nginx/sites-available/secubox-round "$ROOT_MNT/etc/nginx/sites-enabled/"
    rm -f "$ROOT_MNT/etc/nginx/sites-enabled/default"
else
    log "Skipping nginx (framebuffer mode)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# INSTALL DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════

log "Installing Eye Remote dashboard..."

mkdir -p "$ROOT_MNT/var/www/secubox-round"
cp "$SCRIPT_DIR/index.html" "$ROOT_MNT/var/www/secubox-round/"

# Copy assets if they exist
if [[ -d "$SCRIPT_DIR/assets" ]]; then
    cp -r "$SCRIPT_DIR/assets" "$ROOT_MNT/var/www/secubox-round/"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# SSH KEY
# ═══════════════════════════════════════════════════════════════════════════════

if [[ -n "$SSH_PUBKEY" && -f "$SSH_PUBKEY" ]]; then
    log "Installing SSH key..."
    mkdir -p "$ROOT_MNT/home/pi/.ssh"
    cp "$SSH_PUBKEY" "$ROOT_MNT/home/pi/.ssh/authorized_keys"
    chmod 700 "$ROOT_MNT/home/pi/.ssh"
    chmod 600 "$ROOT_MNT/home/pi/.ssh/authorized_keys"
    chroot "$ROOT_MNT" chown -R pi:pi /home/pi/.ssh
fi

# ═══════════════════════════════════════════════════════════════════════════════
# CLEANUP AND FINALIZE
# ═══════════════════════════════════════════════════════════════════════════════

log "Cleaning up chroot..."

# Remove QEMU binary
rm -f "$ROOT_MNT/usr/bin/qemu-arm-static"
rm -f "$ROOT_MNT/tmp/install-packages.sh"
rm -f "$ROOT_MNT/tmp/setup-user.sh"

# Unmount special filesystems
umount "$ROOT_MNT/boot/firmware" 2>/dev/null || true
umount "$ROOT_MNT/dev/pts" 2>/dev/null || true
umount "$ROOT_MNT/dev" 2>/dev/null || true
umount "$ROOT_MNT/proc" 2>/dev/null || true
umount "$ROOT_MNT/sys" 2>/dev/null || true

log "Syncing..."
sync

# Unmount main partitions
umount "$ROOT_MNT"
umount "$BOOT_MNT"

# Run fsck
log "Running filesystem check..."
e2fsck -f -y "${LOOP_DEV}p2" 2>/dev/null || true

# Copy final image
log "Creating final image..."
cp "$WORK_IMG" "$OUTPUT_PATH"
rm -f "$WORK_IMG"

# Reset trap (cleanup already done)
trap - EXIT
losetup -d "$LOOP_DEV" 2>/dev/null || true
rm -rf "$BOOT_MNT" "$ROOT_MNT" 2>/dev/null || true

log ""
log "═══════════════════════════════════════════════════════════════"
log "SecuBox Eye Remote image built successfully! (OFFLINE MODE)"
log "═══════════════════════════════════════════════════════════════"
log ""
log "Output: $OUTPUT_PATH"
log "Size:   $(du -h "$OUTPUT_PATH" | cut -f1)"
log ""
log "Flash to SD card:"
log "  sudo dd if=$OUTPUT_PATH of=/dev/sdX bs=4M status=progress"
log ""
log "Or compress first:"
log "  xz -9 -v $OUTPUT_PATH"
log "  xzcat ${OUTPUT_PATH}.xz | sudo dd of=/dev/sdX bs=4M status=progress"
log ""
info "OFFLINE MODE: No internet required at boot!"
info "All packages pre-installed. Dashboard ready immediately."
log ""
log "First boot:"
log "  1. Insert SD in Pi Zero W with HyperPixel"
log "  2. Connect USB DATA port (middle) to host"
log "  3. Wait ~60s for boot"
log "  4. Dashboard displays automatically"
log ""
log "SSH access (credentials: pi / raspberry):"
log "  ssh pi@10.55.0.2           # Via USB OTG"
if [[ -n "$WIFI_SSID" ]]; then
log "  ssh pi@$HOSTNAME.local     # Via WiFi ($WIFI_SSID)"
fi
log ""
log "USB Gadget modes:"
log "  sudo secubox-otg-gadget.sh start  # Normal"
log "  sudo secubox-otg-gadget.sh tty    # HID Keyboard"
log "  sudo secubox-otg-gadget.sh debug  # Network + Storage"
log "  sudo secubox-otg-gadget.sh flash  # Bootable USB"
log "  sudo secubox-otg-gadget.sh auth   # FIDO2 Security Key"
log ""
