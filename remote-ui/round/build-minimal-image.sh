#!/bin/bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# ═══════════════════════════════════════════════════════════════════════════════
# SecuBox Eye Remote — Minimal Debian Image Builder
# Creates a lightweight Debian bookworm image for RPi Zero W + HyperPixel 2.1 Round
#
# Target: ~200MB image vs ~1.5GB Raspberry Pi OS
# Boot time: ~8s vs ~45s
# RAM usage: ~60MB vs ~180MB
#
# CyberMind — https://cybermind.fr
# Author: Gérald Kerma <gandalf@gk2.net>
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}[eye-build]${NC} $*"; }
ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }

# ═══════════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════════

SUITE="bookworm"
ARCH="armhf"  # Pi Zero W is ARMv6 but armhf works
HOSTNAME="eye-remote"
OUTPUT_DIR="${SCRIPT_DIR}/output"
WORK_DIR=""
IMAGE_SIZE="512M"  # Minimal image size
IMAGE_NAME="eye-remote-minimal-${SUITE}.img"

# Raspberry Pi firmware
RPI_FIRMWARE_REPO="https://github.com/raspberrypi/firmware/raw/master/boot"

# ═══════════════════════════════════════════════════════════════════════════════
# Minimal package list - absolute minimum for Eye Remote
# ═══════════════════════════════════════════════════════════════════════════════

# Stage 1: Absolute minimum for boot
DEBOOTSTRAP_INCLUDE="systemd,systemd-sysv,udev,kmod"

# Stage 2: Essential system
ESSENTIAL_PKGS="
    openssh-server
    sudo
    ca-certificates
    curl
    wpasupplicant
    wireless-tools
    iw
    iproute2
    iputils-ping
    dnsutils
    netbase
    ifupdown
    dhcpcd5
"

# Stage 3: Python minimal (for Eye Remote agent)
PYTHON_PKGS="
    python3-minimal
    python3-pip
    python3-pil
    python3-aiohttp
    python3-toml
"

# Stage 4: Display support
DISPLAY_PKGS="
    fbset
    libdrm2
    fonts-dejavu-core
"

# ═══════════════════════════════════════════════════════════════════════════════
# Functions
# ═══════════════════════════════════════════════════════════════════════════════

check_root() {
    if [[ $EUID -ne 0 ]]; then
        err "This script must be run as root"
        exit 1
    fi
}

check_deps() {
    local deps="debootstrap qemu-user-static binfmt-support parted dosfstools e2fsprogs"
    local missing=""

    for dep in $deps; do
        if ! dpkg -l "$dep" &>/dev/null; then
            missing="$missing $dep"
        fi
    done

    if [[ -n "$missing" ]]; then
        log "Installing dependencies:$missing"
        apt-get update -qq
        apt-get install -y $missing
    fi

    # Ensure binfmt is registered for ARM
    if [[ ! -f /proc/sys/fs/binfmt_misc/qemu-arm ]]; then
        update-binfmts --enable qemu-arm 2>/dev/null || true
    fi
}

create_image() {
    log "Creating ${IMAGE_SIZE} image..."

    mkdir -p "${OUTPUT_DIR}"
    local img="${OUTPUT_DIR}/${IMAGE_NAME}"

    # Create sparse image
    truncate -s "${IMAGE_SIZE}" "$img"

    # Partition: 64MB boot (FAT32) + rest root (ext4)
    parted -s "$img" mklabel msdos
    parted -s "$img" mkpart primary fat32 1MiB 65MiB
    parted -s "$img" mkpart primary ext4 65MiB 100%
    parted -s "$img" set 1 boot on

    ok "Image created: $img"
    echo "$img"
}

setup_loop() {
    local img="$1"

    log "Setting up loop device..."
    local loop=$(losetup -f --show -P "$img")

    # Wait for partitions
    sleep 1
    partprobe "$loop" 2>/dev/null || true
    sleep 1

    echo "$loop"
}

format_partitions() {
    local loop="$1"

    log "Formatting partitions..."
    mkfs.vfat -F 32 -n BOOT "${loop}p1"
    mkfs.ext4 -L rootfs -O ^has_journal "${loop}p2"  # No journal = faster, less writes

    ok "Partitions formatted"
}

mount_partitions() {
    local loop="$1"

    WORK_DIR=$(mktemp -d)
    local rootfs="${WORK_DIR}/rootfs"
    local boot="${WORK_DIR}/rootfs/boot/firmware"

    mkdir -p "$rootfs"
    mount "${loop}p2" "$rootfs"
    mkdir -p "$boot"
    mount "${loop}p1" "$boot"

    echo "$rootfs"
}

run_debootstrap() {
    local rootfs="$1"

    log "Running debootstrap (minimal ${SUITE} ${ARCH})..."

    debootstrap \
        --arch="${ARCH}" \
        --variant=minbase \
        --include="${DEBOOTSTRAP_INCLUDE}" \
        --foreign \
        "${SUITE}" \
        "$rootfs" \
        http://deb.debian.org/debian

    # Copy qemu for second stage
    cp /usr/bin/qemu-arm-static "${rootfs}/usr/bin/"

    # Run second stage
    log "Running debootstrap second stage..."
    chroot "$rootfs" /debootstrap/debootstrap --second-stage

    ok "Debootstrap complete"
}

configure_apt() {
    local rootfs="$1"

    log "Configuring APT sources..."

    cat > "${rootfs}/etc/apt/sources.list" << EOF
deb http://deb.debian.org/debian ${SUITE} main contrib non-free non-free-firmware
deb http://deb.debian.org/debian ${SUITE}-updates main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security ${SUITE}-security main contrib non-free non-free-firmware
EOF

    # Raspberry Pi archive for kernel
    cat > "${rootfs}/etc/apt/sources.list.d/raspi.list" << EOF
deb http://archive.raspberrypi.com/debian ${SUITE} main
EOF

    # Add RPi archive key
    curl -fsSL https://archive.raspberrypi.com/debian/raspberrypi.gpg.key | \
        chroot "$rootfs" gpg --dearmor -o /usr/share/keyrings/raspberrypi-archive-keyring.gpg

    sed -i 's|^deb |deb [signed-by=/usr/share/keyrings/raspberrypi-archive-keyring.gpg] |' \
        "${rootfs}/etc/apt/sources.list.d/raspi.list"
}

install_packages() {
    local rootfs="$1"

    log "Installing essential packages..."

    # Update package lists
    chroot "$rootfs" apt-get update -qq

    # Install in stages to minimize size
    chroot "$rootfs" apt-get install -y --no-install-recommends $ESSENTIAL_PKGS
    ok "Essential packages installed"

    log "Installing Python packages..."
    chroot "$rootfs" apt-get install -y --no-install-recommends $PYTHON_PKGS
    ok "Python packages installed"

    log "Installing display packages..."
    chroot "$rootfs" apt-get install -y --no-install-recommends $DISPLAY_PKGS
    ok "Display packages installed"

    # Install RPi kernel and firmware
    log "Installing Raspberry Pi kernel..."
    chroot "$rootfs" apt-get install -y --no-install-recommends \
        raspberrypi-kernel \
        raspberrypi-bootloader \
        firmware-brcm80211
    ok "Kernel installed"

    # Clean up
    chroot "$rootfs" apt-get clean
    rm -rf "${rootfs}/var/lib/apt/lists/"*
    rm -rf "${rootfs}/var/cache/apt/archives/"*.deb
}

configure_system() {
    local rootfs="$1"

    log "Configuring system..."

    # Hostname
    echo "$HOSTNAME" > "${rootfs}/etc/hostname"
    cat > "${rootfs}/etc/hosts" << EOF
127.0.0.1   localhost
127.0.1.1   ${HOSTNAME}
::1         localhost ip6-localhost ip6-loopback
EOF

    # Timezone
    ln -sf /usr/share/zoneinfo/Europe/Paris "${rootfs}/etc/localtime"
    echo "Europe/Paris" > "${rootfs}/etc/timezone"

    # Locale (minimal)
    echo "en_US.UTF-8 UTF-8" > "${rootfs}/etc/locale.gen"
    chroot "$rootfs" locale-gen
    echo "LANG=en_US.UTF-8" > "${rootfs}/etc/default/locale"

    # Create user
    chroot "$rootfs" useradd -m -s /bin/bash -G sudo,video,gpio,i2c,spi pi
    echo "pi:raspberry" | chroot "$rootfs" chpasswd

    # Root password
    echo "root:secubox" | chroot "$rootfs" chpasswd

    # Sudo without password for pi
    echo "pi ALL=(ALL) NOPASSWD:ALL" > "${rootfs}/etc/sudoers.d/pi"

    # SSH
    chroot "$rootfs" systemctl enable ssh

    # Enable hardware interfaces
    cat >> "${rootfs}/boot/firmware/config.txt" << 'EOF'

# SecuBox Eye Remote Configuration
# ─────────────────────────────────

# HyperPixel 2.1 Round (480x480)
dtoverlay=hyperpixel2r
dtoverlay=hyperpixel2r-touch

# Enable I2C and SPI
dtparam=i2c_arm=on
dtparam=spi=on

# USB OTG gadget mode
dtoverlay=dwc2

# Disable unnecessary
dtparam=audio=off
disable_splash=1

# GPU memory (minimal for framebuffer only)
gpu_mem=32

# Overclock (optional, for responsiveness)
arm_freq=1000
over_voltage=2

# Boot faster
boot_delay=0
disable_poe_fan=1
EOF

    # cmdline.txt
    cat > "${rootfs}/boot/firmware/cmdline.txt" << 'EOF'
console=serial0,115200 console=tty1 root=/dev/mmcblk0p2 rootfstype=ext4 elevator=deadline fsck.repair=yes rootwait quiet init=/usr/lib/raspi-config/init_resize.sh modules-load=dwc2,g_ether
EOF

    ok "System configured"
}

configure_usb_gadget() {
    local rootfs="$1"

    log "Configuring USB OTG gadget..."

    # Load modules at boot
    cat >> "${rootfs}/etc/modules" << EOF
dwc2
libcomposite
EOF

    # Network interface for USB gadget
    cat > "${rootfs}/etc/network/interfaces.d/usb0" << 'EOF'
allow-hotplug usb0
iface usb0 inet static
    address 10.55.0.2
    netmask 255.255.255.252
    gateway 10.55.0.1
EOF

    # USB gadget setup script
    cat > "${rootfs}/usr/local/bin/usb-gadget-setup" << 'GADGET'
#!/bin/bash
# USB Composite Gadget: ECM (network) + ACM (serial)

GADGET_DIR="/sys/kernel/config/usb_gadget/eye-remote"

setup_gadget() {
    # Load configfs
    modprobe libcomposite

    # Create gadget
    mkdir -p "$GADGET_DIR"
    cd "$GADGET_DIR"

    # USB IDs (SecuBox Eye Remote)
    echo 0x1d6b > idVendor   # Linux Foundation
    echo 0x0104 > idProduct  # Composite Gadget
    echo 0x0100 > bcdDevice
    echo 0x0200 > bcdUSB

    # Device info
    mkdir -p strings/0x409
    echo "SecuBox" > strings/0x409/manufacturer
    echo "Eye Remote" > strings/0x409/product
    cat /proc/cpuinfo | grep Serial | cut -d: -f2 | tr -d ' ' > strings/0x409/serialnumber

    # ECM function (Ethernet)
    mkdir -p functions/ecm.usb0

    # ACM function (Serial console)
    mkdir -p functions/acm.usb0

    # Configuration
    mkdir -p configs/c.1/strings/0x409
    echo "ECM+ACM" > configs/c.1/strings/0x409/configuration
    echo 250 > configs/c.1/MaxPower

    # Link functions
    ln -s functions/ecm.usb0 configs/c.1/
    ln -s functions/acm.usb0 configs/c.1/

    # Enable gadget
    ls /sys/class/udc > UDC

    # Bring up network
    sleep 1
    ip link set usb0 up
    ip addr add 10.55.0.2/30 dev usb0 2>/dev/null || true
}

setup_gadget
GADGET
    chmod +x "${rootfs}/usr/local/bin/usb-gadget-setup"

    # Systemd service
    cat > "${rootfs}/etc/systemd/system/usb-gadget.service" << 'EOF'
[Unit]
Description=USB Composite Gadget (ECM+ACM)
After=local-fs.target
Before=network-pre.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/usb-gadget-setup
RemainAfterExit=yes

[Install]
WantedBy=sysinit.target
EOF
    chroot "$rootfs" systemctl enable usb-gadget.service

    ok "USB gadget configured"
}

install_eye_remote() {
    local rootfs="$1"

    log "Installing Eye Remote agent..."

    # Create directories
    mkdir -p "${rootfs}/opt/eye-remote/agent"
    mkdir -p "${rootfs}/var/lib/eye-remote"
    mkdir -p "${rootfs}/etc/eye-remote"

    # Copy agent files
    if [[ -d "${SCRIPT_DIR}/agent" ]]; then
        cp -r "${SCRIPT_DIR}/agent/"* "${rootfs}/opt/eye-remote/agent/"
        ok "Agent files copied"
    else
        warn "Agent directory not found, skipping"
    fi

    # Default config
    cat > "${rootfs}/etc/eye-remote/config.toml" << 'EOF'
[device]
id = "eye-remote-001"
name = "Eye Remote"

[display]
width = 480
height = 480
fps = 30
brightness = 80

[secubox]
host = "10.55.0.1"
port = 8000
poll_interval = 2.0
EOF

    # Systemd service
    cat > "${rootfs}/etc/systemd/system/eye-remote.service" << 'EOF'
[Unit]
Description=SecuBox Eye Remote Dashboard
After=network.target usb-gadget.service
Wants=usb-gadget.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/eye-remote
ExecStart=/usr/bin/python3 -m agent.main --config /etc/eye-remote/config.toml
Restart=always
RestartSec=3
Environment=PYTHONPATH=/opt/eye-remote

[Install]
WantedBy=multi-user.target
EOF
    chroot "$rootfs" systemctl enable eye-remote.service

    ok "Eye Remote installed"
}

optimize_for_speed() {
    local rootfs="$1"

    log "Optimizing for speed..."

    # Disable unnecessary services
    local disable_services="
        apt-daily.timer
        apt-daily-upgrade.timer
        man-db.timer
        e2scrub_all.timer
        systemd-timesyncd
        ModemManager
        bluetooth
    "

    for svc in $disable_services; do
        chroot "$rootfs" systemctl disable "$svc" 2>/dev/null || true
        chroot "$rootfs" systemctl mask "$svc" 2>/dev/null || true
    done

    # Faster boot: disable wait for network
    chroot "$rootfs" systemctl disable systemd-networkd-wait-online.service 2>/dev/null || true

    # Reduce kernel logging
    echo "kernel.printk = 3 4 1 3" >> "${rootfs}/etc/sysctl.d/99-quiet.conf"

    # Disable kernel modules we don't need
    cat > "${rootfs}/etc/modprobe.d/blacklist-eye.conf" << 'EOF'
# Disable unused modules for Eye Remote
blacklist bluetooth
blacklist btbcm
blacklist hci_uart
blacklist snd_bcm2835
blacklist snd_pcm
blacklist snd_timer
blacklist snd
EOF

    # Optimize systemd
    mkdir -p "${rootfs}/etc/systemd/system.conf.d"
    cat > "${rootfs}/etc/systemd/system.conf.d/optimize.conf" << 'EOF'
[Manager]
DefaultTimeoutStartSec=15s
DefaultTimeoutStopSec=10s
EOF

    # Read-only root preparation (optional, for reliability)
    # Can be enabled later with overlay filesystem

    ok "Optimizations applied"
}

cleanup() {
    local rootfs="$1"

    log "Cleaning up..."

    # Remove qemu
    rm -f "${rootfs}/usr/bin/qemu-arm-static"

    # Remove apt cache
    rm -rf "${rootfs}/var/cache/apt/"*
    rm -rf "${rootfs}/var/lib/apt/lists/"*

    # Remove logs
    rm -rf "${rootfs}/var/log/"*.log
    rm -rf "${rootfs}/var/log/"*.gz

    # Remove docs
    rm -rf "${rootfs}/usr/share/doc/"*
    rm -rf "${rootfs}/usr/share/man/"*
    rm -rf "${rootfs}/usr/share/info/"*
    rm -rf "${rootfs}/usr/share/locale/"*

    # Sync
    sync

    ok "Cleanup complete"
}

unmount_all() {
    log "Unmounting..."

    if [[ -n "${WORK_DIR:-}" ]] && [[ -d "${WORK_DIR}/rootfs" ]]; then
        umount "${WORK_DIR}/rootfs/boot/firmware" 2>/dev/null || true
        umount "${WORK_DIR}/rootfs" 2>/dev/null || true
        rm -rf "${WORK_DIR}"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════

main() {
    log "SecuBox Eye Remote Minimal Image Builder v${VERSION}"
    log "═══════════════════════════════════════════════════════════════"

    check_root
    check_deps

    trap unmount_all EXIT

    # Create image
    local img=$(create_image)

    # Setup loop device
    local loop=$(setup_loop "$img")
    log "Loop device: $loop"

    # Format
    format_partitions "$loop"

    # Mount
    local rootfs=$(mount_partitions "$loop")
    log "Rootfs: $rootfs"

    # Debootstrap
    run_debootstrap "$rootfs"

    # Configure APT
    configure_apt "$rootfs"

    # Install packages
    install_packages "$rootfs"

    # Configure system
    configure_system "$rootfs"

    # USB gadget
    configure_usb_gadget "$rootfs"

    # Install Eye Remote
    install_eye_remote "$rootfs"

    # Optimize
    optimize_for_speed "$rootfs"

    # Cleanup
    cleanup "$rootfs"

    # Unmount
    unmount_all

    # Detach loop
    losetup -d "$loop"

    log "═══════════════════════════════════════════════════════════════"
    ok "Image built: ${OUTPUT_DIR}/${IMAGE_NAME}"
    log "Size: $(du -h "${OUTPUT_DIR}/${IMAGE_NAME}" | cut -f1)"
    log ""
    log "Flash with:"
    log "  sudo dd if=${OUTPUT_DIR}/${IMAGE_NAME} of=/dev/sdX bs=4M status=progress"
    log ""
    log "Or compress first:"
    log "  xz -9 -T0 ${OUTPUT_DIR}/${IMAGE_NAME}"
}

main "$@"
