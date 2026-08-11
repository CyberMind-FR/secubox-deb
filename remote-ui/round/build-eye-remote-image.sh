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
VERSION="2.2.1"
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
HOSTNAME="${HOSTNAME:-eye-remote}"
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
    python3-evdev
    pigpio
    # PIL runtime dependencies (v2.2.1 fix)
    libopenjp2-7
    libtiff6
    # Utilities
    i2c-tools
    # Fonts
    fonts-dejavu-core
    # v2.1.0: TFTP for boot media
    dnsmasq-base
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
  -h, --hostname NAME     Hostname (default: eye-remote)
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
# Note: IMAGE_EXPAND_MB must account for embedded storage.img (~2.5GB)
if [[ "$BUILD_MODE" == "browser" ]]; then
    log "Build mode: BROWSER (Chromium kiosk)"
    PACKAGES=("${PACKAGES_FRAMEBUFFER[@]}" "${PACKAGES_BROWSER[@]}")
    IMAGE_EXPAND_MB=4096  # Space for browser + embedded storage.img
else
    log "Build mode: FRAMEBUFFER (Python/PIL direct)"
    PACKAGES=("${PACKAGES_FRAMEBUFFER[@]}")
    IMAGE_EXPAND_MB=3584  # Space for PIL + embedded storage.img (~2.5GB)
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
    parted -s "$WORK_IMG" resizepart 2 100% || warn "parted resizepart warning (may be OK)"
    log "Root partition expanded"
fi

# Setup loop device (redirect stderr to avoid warning polluting LOOP_DEV)
log "Setting up loop device..."
LOOP_DEV=$(losetup -fP --show "$WORK_IMG" 2>/dev/null)
if [[ -z "$LOOP_DEV" ]]; then
    err "Failed to setup loop device"
fi

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

# IMPORTANT: Pi Zero W does NOT support KMS!
# BCM2835 SoC has no VC4 KMS driver - must use legacy DPI mode
log "Configuring HyperPixel 2.1 Round in LEGACY DPI mode (Pi Zero W)"

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
    mkdir -p "$ROOT_MNT/usr/local/sbin"
    cp "$SCRIPT_DIR/hyperpixel/hyperpixel2r-init" "$ROOT_MNT/usr/local/sbin/"
    chmod +x "$ROOT_MNT/usr/local/sbin/hyperpixel2r-init"

    # Verify copy succeeded
    if [[ ! -f "$ROOT_MNT/usr/local/sbin/hyperpixel2r-init" ]]; then
        err "Failed to copy hyperpixel2r-init to rootfs!"
    fi

    # Copy service file (with correct path)
    mkdir -p "$ROOT_MNT/etc/systemd/system"
    cat > "$ROOT_MNT/etc/systemd/system/hyperpixel2r-init.service" << 'HPSERVICE'
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
# CRITICAL: NO restart - one-time init only (restart causes kernel panic)

[Install]
WantedBy=multi-user.target
HPSERVICE

    # Create pigpiod override to fix IPv6-only binding and add delay
    # Fixes: systemd cycle + pigpiod listening on IPv6 only
    mkdir -p "$ROOT_MNT/etc/systemd/system/pigpiod.service.d"
    cat > "$ROOT_MNT/etc/systemd/system/pigpiod.service.d/override.conf" << 'PIGPIOOVERRIDE'
[Unit]
# Use basic.target to avoid ordering cycle with multi-user.target
After=basic.target sysinit.target

[Service]
ExecStart=
# Wait 8 seconds for DPI overlay to stabilize before GPIO access
ExecStartPre=/bin/sleep 8
# No -l flag: must listen on IPv4 for Python pigpio library
ExecStart=/usr/bin/pigpiod
PIGPIOOVERRIDE
    log "Created pigpiod override for IPv4 binding and delay"

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

# Clean existing config - ROBUST cleanup
log "Cleaning existing HyperPixel/KMS config from config.txt..."

# Remove any previous SecuBox Eye Remote section (everything after the marker)
sed -i '/^# === SecuBox Eye Remote/,$d' "$BOOT_MNT/config.txt" 2>/dev/null || true

# Remove KMS overlays (Pi Zero W doesn't support KMS!)
sed -i '/dtoverlay=vc4-kms-v3d/d' "$BOOT_MNT/config.txt" 2>/dev/null || true
sed -i '/dtoverlay=vc4-fkms-v3d/d' "$BOOT_MNT/config.txt" 2>/dev/null || true
sed -i '/dtoverlay=vc4-kms-dpi/d' "$BOOT_MNT/config.txt" 2>/dev/null || true

# Remove old hyperpixel references
sed -i '/hyperpixel/d' "$BOOT_MNT/config.txt" 2>/dev/null || true
sed -i '/HyperPixel/d' "$BOOT_MNT/config.txt" 2>/dev/null || true

# Remove old dwc2 host mode
sed -i 's/dtoverlay=dwc2,dr_mode=host/#REMOVED: dtoverlay=dwc2,dr_mode=host/' "$BOOT_MNT/config.txt" 2>/dev/null || true

# Disable auto-detect
sed -i 's/^display_auto_detect=1/display_auto_detect=0/' "$BOOT_MNT/config.txt" 2>/dev/null || true
sed -i 's/^camera_auto_detect=1/camera_auto_detect=0/' "$BOOT_MNT/config.txt" 2>/dev/null || true

# Write HyperPixel config (ALWAYS legacy DPI mode for Pi Zero W)
cat >> "$BOOT_MNT/config.txt" << CONFIGEOF

# === SecuBox Eye Remote v${VERSION} (OFFLINE) ===
# Pi Zero W: NO KMS support, use legacy DPI mode only!
display_auto_detect=0
camera_auto_detect=0
enable_tvout=0
hdmi_blanking=2
gpu_mem=128

# HyperPixel 2.1 Round 480x480 - LEGACY DPI mode
# Uses hyperpixel2r overlay + pigpio init script
# :disable-touch allows Python to access touch controller via I2C
dtoverlay=${HP_OVERLAY}:disable-touch

# Explicit DPI settings (REQUIRED for Pi Zero W - no KMS support!)
# Without these, the framebuffer may not be created
enable_dpi_lcd=1
display_default_lcd=1
dpi_group=2
dpi_mode=87
dpi_output_format=0x7f216
dpi_timings=480 0 10 16 59 480 0 15 60 15 0 0 0 60 0 19200000 6
framebuffer_width=480
framebuffer_height=480

# NOTE: Do NOT enable i2c_arm or spi here!
# They conflict with DPI pins used by HyperPixel display.
# The hyperpixel2r overlay uses i2c10 for touch (software I2C).
# The LCD init uses pigpio software SPI (bit-banging).

# USB OTG Gadget (composite ECM + ACM)
# dr_mode is set via modprobe options in /etc/modprobe.d/secubox-otg.conf
dtoverlay=dwc2
CONFIGEOF

# cmdline.txt: load modules and hide cursor
CMDLINE=$(cat "$BOOT_MNT/cmdline.txt")
if [[ ! "$CMDLINE" == *"modules-load"* ]]; then
    sed -i 's/rootwait/rootwait modules-load=dwc2,libcomposite/' "$BOOT_MNT/cmdline.txt"
fi
# Hide blinking cursor on framebuffer (keep tty for console access)
if [[ ! "$CMDLINE" == *"vt.global_cursor_default"* ]]; then
    sed -i 's/$/ vt.global_cursor_default=0/' "$BOOT_MNT/cmdline.txt"
fi
# Disable USB autosuspend for stable MOCHAbin connection
if [[ ! "$CMDLINE" == *"usbcore.autosuspend"* ]]; then
    sed -i 's/$/ usbcore.autosuspend=-1/' "$BOOT_MNT/cmdline.txt"
fi

log "config.txt configured: overlay=$HP_OVERLAY (legacy DPI mode)"

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

# Create install script with progress output
cat > "$ROOT_MNT/tmp/install-packages.sh" << 'INSTALLSCRIPT'
#!/bin/bash
set -e

export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C

echo "=== [0/5] Cleaning corrupted APT/dpkg state ==="
# Remove corrupted apt lists
rm -rf /var/lib/apt/lists/*
mkdir -p /var/lib/apt/lists/partial
rm -f /var/cache/apt/*.bin

# Fix dpkg if corrupted
if ! dpkg --configure -a 2>/dev/null; then
    echo "Rebuilding dpkg status..."
    # Backup and rebuild dpkg status if completely broken
    if [ -f /var/lib/dpkg/status ]; then
        cp /var/lib/dpkg/status /var/lib/dpkg/status.bak 2>/dev/null || true
    fi
    # Try to recover from available
    if [ -f /var/lib/dpkg/available ]; then
        cp /var/lib/dpkg/available /var/lib/dpkg/status 2>/dev/null || true
    fi
    dpkg --configure -a 2>/dev/null || true
fi

# Ensure dpkg status exists and is valid
touch /var/lib/dpkg/status
chmod 644 /var/lib/dpkg/status

echo "APT/dpkg cleanup done"

echo "=== [1/5] Updating APT (this may take a few minutes under QEMU) ==="
apt-get update -q || { echo "APT update failed"; exit 1; }

echo "=== [2/5] Reading package list ==="
PACKAGES=$(cat /tmp/package-list.txt | tr '\n' ' ')
echo "Packages to install: $PACKAGES"

echo "=== [3/5] Installing packages one by one (QEMU is slow, be patient) ==="
INSTALLED=0
FAILED=0
TOTAL_PKGS=$(echo $PACKAGES | wc -w)
PKG_NUM=0
for pkg in $PACKAGES; do
    PKG_NUM=$((PKG_NUM + 1))
    echo "  -> [$PKG_NUM/$TOTAL_PKGS] Installing: $pkg"
    # Don't use 2>/dev/null - it can cause buffering hangs under QEMU
    if apt-get install -y --no-install-recommends "$pkg"; then
        echo "     OK: $pkg"
        INSTALLED=$((INSTALLED + 1))
    else
        echo "     WARN: $pkg failed (may be optional)"
        FAILED=$((FAILED + 1))
    fi
    # Flush output after each package
    sync
done
echo "  Installed: $INSTALLED, Failed: $FAILED"

echo "=== [3.5/5] Installing Python packages via pip ==="
# These packages are not in Debian repos, install via pip
pip3 install httpx fastapi uvicorn websockets hyperpixel2r smbus2 --break-system-packages --no-cache-dir || echo "WARN: pip install failed"

echo "=== [4/5] Enabling pigpiod ==="
systemctl enable pigpiod || true

echo "=== [5/5] Cleaning APT cache ==="
apt-get clean
rm -rf /var/lib/apt/lists/*
rm -f /tmp/package-list.txt

echo "=== Package installation complete ==="
INSTALLSCRIPT
chmod +x "$ROOT_MNT/tmp/install-packages.sh"

# Run install in chroot with timeout (20 minutes for QEMU ARM emulation)
log "Running package installation in QEMU chroot (this takes 10-20 minutes)..."
log "Progress will be shown below. If it hangs > 20min, check network/DNS."

CHROOT_LOG="/tmp/eye-remote-chroot-install.log"

# IMPORTANT: Don't use "timeout ... | tee" - it causes hangs!
# The timeout only applies to the left side of the pipe, not tee.
# Instead, redirect to file and tail in background for live output.
rm -f "$CHROOT_LOG"
touch "$CHROOT_LOG"

# Start tail in background to show live output
tail -f "$CHROOT_LOG" &
TAIL_PID=$!

# Run chroot directly to file (stdbuf doesn't work with chroot)
if timeout --kill-after=60s 1200s chroot "$ROOT_MNT" /tmp/install-packages.sh > "$CHROOT_LOG" 2>&1; then
    kill $TAIL_PID 2>/dev/null || true
    wait $TAIL_PID 2>/dev/null || true
    log "Package installation completed successfully"
else
    kill $TAIL_PID 2>/dev/null || true
    wait $TAIL_PID 2>/dev/null || true
    err "Package installation failed or timed out (see $CHROOT_LOG)"
    tail -20 "$CHROOT_LOG" || true
    exit 1
fi

# Remove policy
rm -f "$ROOT_MNT/usr/sbin/policy-rc.d"

log "Packages installed successfully"

# ═══════════════════════════════════════════════════════════════════════════════
# NOTE: Eye Remote is a standalone gadget addon - no SecuBox packages needed
# The Eye Remote connects to SecuBox via USB OTG and displays metrics
# ═══════════════════════════════════════════════════════════════════════════════

log "Eye Remote is standalone gadget - skipping SecuBox packages"

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
i2c-dev
usb_f_hid
EOF

# Modprobe config
mkdir -p "$ROOT_MNT/etc/modprobe.d"
cat > "$ROOT_MNT/etc/modprobe.d/secubox-otg.conf" << 'MODPROBECONF'
# SecuBox Eye Remote USB Gadget Mode
options dwc2 dr_mode=peripheral
# Disable USB autosuspend for stable connection
options usbcore autosuspend=-1
MODPROBECONF

# NOTE: configfs is mounted by gadget-setup.sh on demand, not via fstab
# Adding it to fstab can cause boot failures if module isn't loaded early enough

# Copy gadget scripts
log "Installing Eye Remote scripts..."
mkdir -p "$ROOT_MNT/usr/local/sbin"
cp "$SCRIPT_DIR/secubox-otg-gadget.sh" "$ROOT_MNT/usr/local/sbin/"
cp "$SCRIPT_DIR/secubox-hid-keyboard.sh" "$ROOT_MNT/usr/local/sbin/"
chmod +x "$ROOT_MNT/usr/local/sbin/secubox-"*.sh

# First-boot hostname script (derives hostname from CPU serial)
cp "$SCRIPT_DIR/files/usr/local/sbin/eye-firstboot-hostname.sh" "$ROOT_MNT/usr/local/sbin/"
chmod +x "$ROOT_MNT/usr/local/sbin/eye-firstboot-hostname.sh"
log "Installed eye-firstboot-hostname.sh"

# Copy v2.1.0 gadget-setup.sh
mkdir -p "$ROOT_MNT/etc/secubox/eye-remote"
cp "$SCRIPT_DIR/files/etc/secubox/eye-remote/gadget-setup.sh" "$ROOT_MNT/etc/secubox/eye-remote/"
cp "$SCRIPT_DIR/files/etc/secubox/eye-remote/tftp.env" "$ROOT_MNT/etc/secubox/eye-remote/"
chmod +x "$ROOT_MNT/etc/secubox/eye-remote/gadget-setup.sh"

# Copy dnsmasq config
mkdir -p "$ROOT_MNT/etc/dnsmasq.d"
cp "$SCRIPT_DIR/files/etc/dnsmasq.d/secubox-eye-tftp.conf" "$ROOT_MNT/etc/dnsmasq.d/"

# Copy systemd-networkd units: rename usb0→eye0 (.link) + DHCP client on eye0 (.network)
mkdir -p "$ROOT_MNT/etc/systemd/network"
cp "$SCRIPT_DIR/files/etc/systemd/network/10-eye0.link" "$ROOT_MNT/etc/systemd/network/"
cp "$SCRIPT_DIR/files/etc/systemd/network/10-eye0.network" "$ROOT_MNT/etc/systemd/network/"
log "Installed 10-eye0.link (rename usb0→eye0) and 10-eye0.network (DHCP client on eye0)"

# First-boot hostname service
cp "$SCRIPT_DIR/files/etc/systemd/system/eye-firstboot-hostname.service" "$ROOT_MNT/etc/systemd/system/"
log "Installed eye-firstboot-hostname.service"

# Copy systemd files
cp "$SCRIPT_DIR/files/etc/systemd/system/secubox-eye-gadget.service" "$ROOT_MNT/etc/systemd/system/"
mkdir -p "$ROOT_MNT/etc/systemd/system/dnsmasq.service.d"
cp "$SCRIPT_DIR/files/etc/systemd/system/dnsmasq.service.d/secubox-eye.conf" \
    "$ROOT_MNT/etc/systemd/system/dnsmasq.service.d/"

# secubox-eye-gadget is STORAGE-only mode for U-Boot rescue. Enabling it
# at boot alongside secubox-otg-gadget.service (composite ECM+ACM) caused
# UDC contention. Install the unit but DO NOT enable at boot.
# Manual U-Boot rescue mode:
#     systemctl disable secubox-otg-gadget.service
#     systemctl enable --now secubox-eye-gadget.service
# ln -sf /etc/systemd/system/secubox-eye-gadget.service \
#     "$ROOT_MNT/etc/systemd/system/multi-user.target.wants/"

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

    # Copy agent modules (all .py files AND subdirectories)
    cp "$SCRIPT_DIR/agent"/*.py "$ROOT_MNT/usr/lib/secubox-eye/agent/" || err "Failed to copy agent modules"

    # Copy agent subdirectories (all required for fallback display)
    for subdir in display secubox system web api recovery sync; do
        if [[ -d "$SCRIPT_DIR/agent/$subdir" ]]; then
            cp -r "$SCRIPT_DIR/agent/$subdir" "$ROOT_MNT/usr/lib/secubox-eye/agent/"
            log "Copied agent/$subdir/"
        fi
    done

    # Copy example config with secure permissions
    cp "$SCRIPT_DIR/config.toml.example" "$ROOT_MNT/etc/secubox-eye/config.toml"
    chmod 600 "$ROOT_MNT/etc/secubox-eye/config.toml"

    # Install agent service
    cp "$SCRIPT_DIR/secubox-eye-agent.service" "$ROOT_MNT/etc/systemd/system/"

    # The agent depends on Pydantic v2 (pydantic_core, Rust) which has no
    # ARMv6 wheel — pip ships an ARMv7 wheel that crashes with SIGILL on
    # the Pi Zero W BCM2835 (status=4/ILL). v2.2.1 design moved metrics
    # rendering to secubox-fallback-display.service (pure-Python Pillow),
    # so we install the unit but DO NOT enable at boot. ARMv7+ boards:
    #     systemctl enable --now secubox-eye-agent.service
    mkdir -p "$ROOT_MNT/etc/systemd/system/multi-user.target.wants"
    # ln -sf /etc/systemd/system/secubox-eye-agent.service \
    #     "$ROOT_MNT/etc/systemd/system/multi-user.target.wants/"

    # v2.2.0: Install menu system icons for radial menu
    if [[ -d "$SCRIPT_DIR/assets/icons" ]]; then
        log "Installing menu system icons..."
        mkdir -p "$ROOT_MNT/usr/lib/secubox-eye/assets/icons"
        cp "$SCRIPT_DIR/assets/icons"/*.png "$ROOT_MNT/usr/lib/secubox-eye/assets/icons/" 2>/dev/null || true
        # Defense-in-depth: also drop the brand-icon PNGs (auth/wall/boot/
        # mind/root/mesh) from remote-ui/common/assets/icons/ so any consumer
        # that resolves icons via /usr/lib/secubox-eye/ finds them. The
        # fallback_manager also searches /var/www/common/assets/icons/
        # directly (where build copies common/ in another step) — this is
        # redundant shipping for resilience.
