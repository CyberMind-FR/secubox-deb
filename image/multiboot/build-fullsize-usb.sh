#!/usr/bin/env bash
# SecuBox Full-Size Multi-Boot USB Builder
# Extends build-multiboot.sh for 32GB+ USB with all profiles
# - ARM64: ESPRESSObin Live + eMMC installer
# - AMD64: Live (VBox-ready) + Kiosk + Installer
# - Shared: SecuBox debs, profiles, ISOs
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT_DIR="${REPO_ROOT}/output"
CACHE_DIR="${REPO_ROOT}/cache"

# Import common functions
source "$SCRIPT_DIR/../lib/common.sh" 2>/dev/null || true

# USB device (will be set by --device)
USB_DEVICE=""
IMAGE_FILE=""
IMAGE_SIZE="32G"
SKIP_CONFIRM=false

# Partition layout (MB) - optimized for 32GB
EFI_SIZE=512
ARM64_SIZE=4096      # 4GB - Live + eMMC flasher
AMD64_LIVE_SIZE=8192 # 8GB - Full system with kiosk
# DATA = remaining (~19GB)

# Build options
BUILD_ARM64=true
BUILD_AMD64=true
INCLUDE_KIOSK=true
INCLUDE_WEBUI=true
INCLUDE_DEBS=true

log() { echo -e "\033[0;36m[$(date '+%H:%M:%S')]\033[0m $*"; }
ok()  { echo -e "\033[0;32m[  OK ]\033[0m $*"; }
err() { echo -e "\033[0;31m[ERROR]\033[0m $*" >&2; exit 1; }
warn() { echo -e "\033[0;33m[WARN]\033[0m $*" >&2; }

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Build SecuBox full-size multi-boot USB (32GB+)

TARGETS:
  --device DEVICE       Write directly to USB device (e.g., /dev/sdb)
  --image FILE          Create image file instead
  --size SIZE           Image size (default: 32G)

OPTIONS:
  --no-arm64            Skip ARM64 rootfs
  --no-amd64            Skip AMD64 rootfs
  --no-kiosk            Skip kiosk setup (AMD64)
  --no-webui            Skip WebUI installation
  --no-debs             Skip SecuBox .deb packages
  -y, --yes             Skip confirmation prompts
  -h, --help            Show this help

PROFILES (written to data partition):
  - live-amd64-vbox     VirtualBox-ready live system
  - live-amd64-kiosk    Kiosk mode with dashboard
  - installer-amd64     Install to internal drive
  - installer-ebin      Flash to ESPRESSObin eMMC
  - webui               SecuBox Hub dashboard (all archs)

Example:
  $(basename "$0") --device /dev/sdb -y
  $(basename "$0") --image fullsize.img --size 32G
EOF
    exit 0
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --device)     USB_DEVICE="$2"; shift 2 ;;
            --image)      IMAGE_FILE="$2"; shift 2 ;;
            --size)       IMAGE_SIZE="$2"; shift 2 ;;
            --no-arm64)   BUILD_ARM64=false; shift ;;
            --no-amd64)   BUILD_AMD64=false; shift ;;
            --no-kiosk)   INCLUDE_KIOSK=false; shift ;;
            --no-webui)   INCLUDE_WEBUI=false; shift ;;
            --no-debs)    INCLUDE_DEBS=false; shift ;;
            -y|--yes)     SKIP_CONFIRM=true; shift ;;
            -h|--help)    usage ;;
            *)            err "Unknown option: $1" ;;
        esac
    done

    [[ -n "$USB_DEVICE" || -n "$IMAGE_FILE" ]] || err "Specify --device or --image"
    [[ -z "$USB_DEVICE" || -b "$USB_DEVICE" ]] || err "Not a block device: $USB_DEVICE"
}

check_deps() {
    local deps=(parted mkfs.vfat mkfs.ext4 debootstrap rsync mkimage)
    for cmd in "${deps[@]}"; do
        command -v "$cmd" &>/dev/null || err "Missing: $cmd"
    done
    [[ $EUID -eq 0 ]] || err "Must run as root"
}

confirm_destructive() {
    [[ "$SKIP_CONFIRM" == "true" ]] && return 0

    if [[ -n "$USB_DEVICE" ]]; then
        log "WARNING: This will ERASE ALL DATA on $USB_DEVICE"
        lsblk "$USB_DEVICE" 2>/dev/null || true
        read -p "Type 'YES' to confirm: " confirm
        [[ "$confirm" == "YES" ]] || err "Aborted"
    fi
}

setup_target() {
    if [[ -n "$USB_DEVICE" ]]; then
        TARGET="$USB_DEVICE"
        log "Target: USB device $TARGET"
    else
        TARGET="$IMAGE_FILE"
        log "Creating ${IMAGE_SIZE} image: $TARGET"
        mkdir -p "$(dirname "$TARGET")"
        truncate -s "$IMAGE_SIZE" "$TARGET"
    fi
}

partition_target() {
    log "Partitioning target..."

    # Wipe existing
    wipefs -a "$TARGET" &>/dev/null || true

    parted -s "$TARGET" mklabel gpt

    local start=1
    local end=$((start + EFI_SIZE))

    # P1: EFI System Partition (ESP)
    parted -s "$TARGET" mkpart ESP fat32 ${start}MiB ${end}MiB
    parted -s "$TARGET" set 1 esp on
    parted -s "$TARGET" set 1 boot on
    start=$end

    # P2: ARM64 rootfs
    end=$((start + ARM64_SIZE))
    parted -s "$TARGET" mkpart ARM64 ext4 ${start}MiB ${end}MiB
    start=$end

    # P3: AMD64 Live rootfs
    end=$((start + AMD64_LIVE_SIZE))
    parted -s "$TARGET" mkpart AMD64 ext4 ${start}MiB ${end}MiB
    start=$end

    # P4: Shared Data (remaining)
    parted -s "$TARGET" mkpart DATA ext4 ${start}MiB 100%

    parted -s "$TARGET" print
    ok "Partitioned: EFI(${EFI_SIZE}M) ARM64(${ARM64_SIZE}M) AMD64(${AMD64_LIVE_SIZE}M) DATA(remaining)"
}

setup_loop() {
    if [[ -n "$IMAGE_FILE" ]]; then
        LOOP_DEV=$(losetup -f --show -P "$TARGET")
        P_EFI="${LOOP_DEV}p1"
        P_ARM64="${LOOP_DEV}p2"
        P_AMD64="${LOOP_DEV}p3"
        P_DATA="${LOOP_DEV}p4"
        log "Loop device: $LOOP_DEV"
    else
        partprobe "$TARGET" 2>/dev/null || sleep 2
        P_EFI="${TARGET}1"
        P_ARM64="${TARGET}2"
        P_AMD64="${TARGET}3"
        P_DATA="${TARGET}4"
    fi
}

format_partitions() {
    log "Formatting partitions..."

    mkfs.vfat -F 32 -n SECUBOX-EFI "$P_EFI"
    mkfs.ext4 -F -L SECUBOX-ARM64 "$P_ARM64"
    mkfs.ext4 -F -L SECUBOX-AMD64 "$P_AMD64"
    mkfs.ext4 -F -L SECUBOX-DATA "$P_DATA"

    ok "Formatted all partitions"
}

mount_partitions() {
    MNT_EFI=$(mktemp -d)
    MNT_ARM64=$(mktemp -d)
    MNT_AMD64=$(mktemp -d)
    MNT_DATA=$(mktemp -d)

    mount "$P_EFI" "$MNT_EFI"
    mount "$P_ARM64" "$MNT_ARM64"
    mount "$P_AMD64" "$MNT_AMD64"
    mount "$P_DATA" "$MNT_DATA"

    log "Mounted: EFI→$MNT_EFI ARM64→$MNT_ARM64 AMD64→$MNT_AMD64 DATA→$MNT_DATA"
}

cleanup() {
    log "Cleanup..."
    sync

    for mnt in "$MNT_EFI" "$MNT_ARM64" "$MNT_AMD64" "$MNT_DATA"; do
        [[ -n "$mnt" && -d "$mnt" ]] && { umount "$mnt" 2>/dev/null || true; rmdir "$mnt" 2>/dev/null || true; }
    done

    [[ -n "${LOOP_DEV:-}" ]] && losetup -d "$LOOP_DEV" 2>/dev/null || true
}
trap cleanup EXIT

# ─────────────────────────────────────────────────────────────────────
# EFI Partition Setup (GRUB + U-Boot)
# ─────────────────────────────────────────────────────────────────────
setup_efi_partition() {
    log "Setting up EFI partition..."

    mkdir -p "$MNT_EFI"/{EFI/BOOT,grub,dtbs/marvell,flash}

    # Copy ARM64 kernel from existing live image
    local arm64_img="${OUTPUT_DIR}/secubox-espressobin-v7-live-usb.img"
    if [[ -f "$arm64_img" ]]; then
        log "Extracting ARM64 kernel from live image..."
        local tmp_loop=$(losetup -f --show -P "$arm64_img")
        local tmp_mnt=$(mktemp -d)
        mount "${tmp_loop}p1" "$tmp_mnt"

        cp "$tmp_mnt/Image" "$MNT_EFI/" 2>/dev/null || true
        cp "$tmp_mnt/initrd.img" "$MNT_EFI/" 2>/dev/null || true
        cp -r "$tmp_mnt/dtbs" "$MNT_EFI/" 2>/dev/null || true

        umount "$tmp_mnt"; rmdir "$tmp_mnt"
        losetup -d "$tmp_loop"
        ok "ARM64 kernel extracted"
    else
        warn "ARM64 live image not found, kernel will be missing"
    fi

    # Generate U-Boot boot.scr for ARM64
    create_uboot_script

    # Setup GRUB for AMD64
    setup_grub_efi

    ok "EFI partition ready"
}

create_uboot_script() {
    log "Creating U-Boot boot script..."

    cat > "$MNT_EFI/boot.scr.txt" << 'BOOTSCR'
# SecuBox Multi-Boot U-Boot Script
# ARM64 ESPRESSObin/MOCHAbin

echo "============================================"
echo "SecuBox Multi-Boot - ARM64"
echo "============================================"
echo ""
echo "Boot options:"
echo "  1. Live SecuBox (default)"
echo "  2. Install to eMMC"
echo ""

# Default to live boot
setenv boot_mode "live"

# Detect device
if test "${devtype}" = "usb"; then
    setenv bootpart "usb 0:1"
    setenv rootpart "/dev/sda2"
    setenv datapart "/dev/sda4"
else
    usb start
    setenv bootpart "usb 0:1"
    setenv rootpart "/dev/sda2"
    setenv datapart "/dev/sda4"
fi

# Load kernel
echo "Loading ARM64 kernel..."
load ${bootpart} ${kernel_addr_r} Image

# Load DTB
echo "Loading device tree..."
if load ${bootpart} ${fdt_addr_r} dtbs/marvell/armada-3720-espressobin-v7-emmc.dtb; then
    echo "ESPRESSObin v7 eMMC DTB loaded"
elif load ${bootpart} ${fdt_addr_r} dtbs/marvell/armada-3720-espressobin-v7.dtb; then
    echo "ESPRESSObin v7 DTB loaded"
fi

# Load initramfs
echo "Loading initramfs..."
if load ${bootpart} ${ramdisk_addr_r} initrd.img; then
    setenv initrd_size ${filesize}
    setenv use_initrd 1
else
    setenv use_initrd 0
fi

# Boot arguments with DSA switch blacklist
setenv bootargs "root=${rootpart} rootfstype=ext4 rootwait rootdelay=5 console=ttyMV0,115200 net.ifnames=0 modprobe.blacklist=mv88e6xxx,mv88e6085,dsa_core initcall_blacklist=mv88e6xxx_driver_init secubox.data=${datapart} secubox.profile=webui"

echo "Booting SecuBox ARM64..."
if test "${use_initrd}" = "1"; then
    booti ${kernel_addr_r} ${ramdisk_addr_r}:${initrd_size} ${fdt_addr_r}
else
    booti ${kernel_addr_r} - ${fdt_addr_r}
fi
BOOTSCR

    mkimage -T script -C none -n "SecuBox Boot" -d "$MNT_EFI/boot.scr.txt" "$MNT_EFI/boot.scr"
    ok "U-Boot script created"
}

setup_grub_efi() {
    log "Setting up GRUB for AMD64 UEFI..."

    # Copy GRUB EFI binary
    if [[ -f /usr/lib/grub/x86_64-efi/monolithic/grubx64.efi ]]; then
        cp /usr/lib/grub/x86_64-efi/monolithic/grubx64.efi "$MNT_EFI/EFI/BOOT/BOOTX64.EFI"
    elif [[ -f /boot/efi/EFI/debian/grubx64.efi ]]; then
        cp /boot/efi/EFI/debian/grubx64.efi "$MNT_EFI/EFI/BOOT/BOOTX64.EFI"
    else
        warn "GRUB EFI binary not found, AMD64 boot may not work"
    fi

    # GRUB configuration
    cat > "$MNT_EFI/grub/grub.cfg" << 'GRUBCFG'
set timeout=10
set default=0

insmod part_gpt
insmod ext2
insmod fat

menuentry "SecuBox Live AMD64 (Kiosk Mode)" {
    linux /vmlinuz root=LABEL=SECUBOX-AMD64 ro quiet splash secubox.profile=kiosk
    initrd /initrd-amd64.img
}

menuentry "SecuBox Live AMD64 (WebUI Only)" {
    linux /vmlinuz root=LABEL=SECUBOX-AMD64 ro quiet secubox.profile=webui
    initrd /initrd-amd64.img
}

menuentry "SecuBox AMD64 - Install to Disk" {
    linux /vmlinuz root=LABEL=SECUBOX-AMD64 ro secubox.profile=installer single
    initrd /initrd-amd64.img
}

menuentry "VirtualBox Live (NAT + Host-Only)" {
    linux /vmlinuz root=LABEL=SECUBOX-AMD64 ro quiet secubox.profile=vbox secubox.net=vbox
    initrd /initrd-amd64.img
}
GRUBCFG

    ok "GRUB configured"
}

# ─────────────────────────────────────────────────────────────────────
# ARM64 Rootfs (ESPRESSObin Live + eMMC Installer)
# ─────────────────────────────────────────────────────────────────────
build_arm64_rootfs() {
    [[ "$BUILD_ARM64" != "true" ]] && { log "Skipping ARM64 rootfs"; return 0; }

    log "Building ARM64 rootfs..."

    # Check for existing rootfs or build new
    local arm64_img="${OUTPUT_DIR}/secubox-espressobin-v7-live-usb.img"
    if [[ -f "$arm64_img" ]]; then
        log "Extracting ARM64 rootfs from existing image..."
        local tmp_loop=$(losetup -f --show -P "$arm64_img")
        local tmp_mnt=$(mktemp -d)
        mount "${tmp_loop}p2" "$tmp_mnt" 2>/dev/null || mount "${tmp_loop}p1" "$tmp_mnt"

        rsync -aHAX --info=progress2 "$tmp_mnt/" "$MNT_ARM64/"

        umount "$tmp_mnt"; rmdir "$tmp_mnt"
        losetup -d "$tmp_loop"
    else
        log "No existing ARM64 image, using debootstrap..."
        qemu-debootstrap --arch=arm64 \
            --include=systemd,systemd-sysv,dbus,locales,openssh-server,curl,python3,nginx \
            bookworm "$MNT_ARM64" http://deb.debian.org/debian
    fi

    # Add eMMC flash tools
    setup_emmc_flasher "$MNT_ARM64"

    # Add WebUI
    [[ "$INCLUDE_WEBUI" == "true" ]] && install_webui "$MNT_ARM64"

    ok "ARM64 rootfs ready ($(du -sh "$MNT_ARM64" | cut -f1))"
}

setup_emmc_flasher() {
    local rootfs="$1"
    log "Adding eMMC flasher tools..."

    mkdir -p "$rootfs/usr/local/bin"

    cat > "$rootfs/usr/local/bin/secubox-flash-emmc" << 'FLASHER'
#!/bin/bash
# SecuBox eMMC Flasher for ESPRESSObin
set -euo pipefail

EMMC_DEV="/dev/mmcblk0"
DATA_PART="/dev/sda4"
FLASH_IMG="/mnt/data/flash/secubox-ebin-emmc.img"

echo "╔════════════════════════════════════════╗"
echo "║  SecuBox eMMC Flasher - ESPRESSObin   ║"
echo "╚════════════════════════════════════════╝"
echo ""

# Mount data partition
mkdir -p /mnt/data
mount "$DATA_PART" /mnt/data 2>/dev/null || true

if [[ ! -f "$FLASH_IMG" ]]; then
    echo "ERROR: Flash image not found: $FLASH_IMG"
    echo "Copy your SecuBox image to the DATA partition first."
    exit 1
fi

echo "WARNING: This will ERASE the eMMC on $EMMC_DEV"
echo "Image: $FLASH_IMG ($(ls -lh "$FLASH_IMG" | awk '{print $5}'))"
read -p "Type 'FLASH' to continue: " confirm
[[ "$confirm" == "FLASH" ]] || { echo "Aborted"; exit 1; }

echo "Flashing eMMC..."
dd if="$FLASH_IMG" of="$EMMC_DEV" bs=4M status=progress conv=fsync

echo ""
echo "Flash complete! You can now reboot from eMMC."
echo "Remove USB and run: reboot"
FLASHER
    chmod +x "$rootfs/usr/local/bin/secubox-flash-emmc"

    ok "eMMC flasher installed"
}

# ─────────────────────────────────────────────────────────────────────
# AMD64 Rootfs (Live + Kiosk + Installer)
# ─────────────────────────────────────────────────────────────────────
build_amd64_rootfs() {
    [[ "$BUILD_AMD64" != "true" ]] && { log "Skipping AMD64 rootfs"; return 0; }

    log "Building AMD64 rootfs..."

    # Full debootstrap with desktop components
    debootstrap --arch=amd64 \
        --include=systemd,systemd-sysv,dbus,locales,linux-image-amd64,grub-efi-amd64,\
openssh-server,curl,wget,python3,python3-pip,nginx,\
xorg,xinit,openbox,chromium,fonts-dejavu \
        bookworm "$MNT_AMD64" http://deb.debian.org/debian

    # Basic configuration
    configure_amd64_base "$MNT_AMD64"

    # Install components based on flags
    [[ "$INCLUDE_WEBUI" == "true" ]] && install_webui "$MNT_AMD64"
    [[ "$INCLUDE_KIOSK" == "true" ]] && install_kiosk "$MNT_AMD64"

    # Add disk installer
    install_disk_installer "$MNT_AMD64"

    # Copy kernel to EFI
    local vmlinuz=$(find "$MNT_AMD64/boot" -name 'vmlinuz-*' -type f | sort -V | tail -1)
    local initrd=$(find "$MNT_AMD64/boot" -name 'initrd.img-*' -type f | sort -V | tail -1)
    [[ -n "$vmlinuz" ]] && cp "$vmlinuz" "$MNT_EFI/vmlinuz"
    [[ -n "$initrd" ]] && cp "$initrd" "$MNT_EFI/initrd-amd64.img"

    ok "AMD64 rootfs ready ($(du -sh "$MNT_AMD64" | cut -f1))"
}

configure_amd64_base() {
    local rootfs="$1"
    log "Configuring AMD64 base system..."

    echo "secubox-amd64" > "$rootfs/etc/hostname"

    cat > "$rootfs/etc/hosts" << EOF
127.0.0.1   localhost secubox-amd64
::1         localhost ip6-localhost
EOF

    # Locale
    echo "en_US.UTF-8 UTF-8" > "$rootfs/etc/locale.gen"
    chroot "$rootfs" locale-gen

    # Root password
    echo "root:secubox" | chroot "$rootfs" chpasswd

    # Network
    cat > "$rootfs/etc/network/interfaces" << EOF
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
EOF

    # Profile selector service
    cat > "$rootfs/etc/systemd/system/secubox-profile.service" << 'SVC'
[Unit]
Description=SecuBox Profile Selector
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/secubox-profile-init
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SVC

    cat > "$rootfs/usr/local/bin/secubox-profile-init" << 'PROFILE'
#!/bin/bash
# Parse kernel cmdline for secubox.profile=
PROFILE=$(cat /proc/cmdline | grep -oP 'secubox\.profile=\K\w+' || echo "webui")

case "$PROFILE" in
    kiosk)
        systemctl start secubox-kiosk.service
        ;;
    vbox)
        # VirtualBox optimizations
        systemctl start secubox-kiosk.service
        ;;
    installer)
        /usr/local/bin/secubox-installer
        ;;
    *)
        # Default: just WebUI (nginx)
        systemctl start nginx
        ;;
esac
PROFILE
    chmod +x "$rootfs/usr/local/bin/secubox-profile-init"

    chroot "$rootfs" systemctl enable secubox-profile.service
}

install_kiosk() {
    local rootfs="$1"
    log "Installing kiosk mode..."

    mkdir -p "$rootfs/usr/share/secubox/kiosk"

    # Copy existing kiosk script
    if [[ -f "$REPO_ROOT/image/kiosk/secubox-kiosk.sh" ]]; then
        cp "$REPO_ROOT/image/kiosk/secubox-kiosk.sh" "$rootfs/usr/share/secubox/kiosk/"
        chmod +x "$rootfs/usr/share/secubox/kiosk/secubox-kiosk.sh"
    fi

    # Kiosk systemd service
    cat > "$rootfs/etc/systemd/system/secubox-kiosk.service" << 'SVC'
[Unit]
Description=SecuBox Kiosk Mode
After=graphical.target nginx.service

[Service]
Type=simple
User=kiosk
Environment=DISPLAY=:0
ExecStartPre=/usr/bin/xinit -- :0 vt7 &
ExecStart=/usr/share/secubox/kiosk/secubox-kiosk.sh
Restart=always
RestartSec=5

[Install]
WantedBy=graphical.target
SVC

    # Create kiosk user
    chroot "$rootfs" useradd -m -s /bin/bash kiosk 2>/dev/null || true

    ok "Kiosk mode installed"
}

install_webui() {
    local rootfs="$1"
    log "Installing WebUI..."

    mkdir -p "$rootfs/var/www/secubox"

    # Copy SecuBox Hub frontend if available
    if [[ -d "$REPO_ROOT/packages/secubox-hub/www" ]]; then
        cp -r "$REPO_ROOT/packages/secubox-hub/www/"* "$rootfs/var/www/secubox/"
    fi

    # Nginx config
    cat > "$rootfs/etc/nginx/sites-available/secubox" << 'NGINX'
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    root /var/www/secubox;
    index index.html;

    server_name _;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api/ {
        proxy_pass http://unix:/run/secubox/hub.sock;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
    }
}
NGINX

    ln -sf /etc/nginx/sites-available/secubox "$rootfs/etc/nginx/sites-enabled/secubox"
    rm -f "$rootfs/etc/nginx/sites-enabled/default"

    chroot "$rootfs" systemctl enable nginx

    ok "WebUI installed"
}

install_disk_installer() {
    local rootfs="$1"
    log "Adding disk installer..."

    cat > "$rootfs/usr/local/bin/secubox-installer" << 'INSTALLER'
#!/bin/bash
# SecuBox AMD64 Disk Installer
set -euo pipefail

echo "╔════════════════════════════════════════╗"
echo "║  SecuBox AMD64 Disk Installer         ║"
echo "╚════════════════════════════════════════╝"
echo ""

# List available disks
echo "Available disks:"
lsblk -d -o NAME,SIZE,MODEL | grep -v loop
echo ""

read -p "Enter target disk (e.g., sda, nvme0n1): " TARGET_DISK
TARGET="/dev/$TARGET_DISK"

[[ -b "$TARGET" ]] || { echo "Not a block device: $TARGET"; exit 1; }

echo ""
echo "WARNING: This will ERASE ALL DATA on $TARGET"
read -p "Type 'INSTALL' to continue: " confirm
[[ "$confirm" == "INSTALL" ]] || { echo "Aborted"; exit 1; }

echo "Installing SecuBox to $TARGET..."

# Partition
parted -s "$TARGET" mklabel gpt
parted -s "$TARGET" mkpart ESP fat32 1MiB 512MiB
parted -s "$TARGET" set 1 esp on
parted -s "$TARGET" mkpart root ext4 512MiB 100%

# Format
mkfs.vfat -F 32 "${TARGET}1" 2>/dev/null || mkfs.vfat -F 32 "${TARGET}p1"
mkfs.ext4 -F "${TARGET}2" 2>/dev/null || mkfs.ext4 -F "${TARGET}p2"

# Mount and copy
mkdir -p /mnt/install
mount "${TARGET}2" /mnt/install 2>/dev/null || mount "${TARGET}p2" /mnt/install
mkdir -p /mnt/install/boot/efi
mount "${TARGET}1" /mnt/install/boot/efi 2>/dev/null || mount "${TARGET}p1" /mnt/install/boot/efi

echo "Copying system (this takes a while)..."
rsync -aHAX --info=progress2 --exclude='/proc/*' --exclude='/sys/*' --exclude='/dev/*' \
    --exclude='/run/*' --exclude='/tmp/*' --exclude='/mnt/*' / /mnt/install/

# Install GRUB
mount --bind /dev /mnt/install/dev
mount --bind /proc /mnt/install/proc
mount --bind /sys /mnt/install/sys
chroot /mnt/install grub-install --target=x86_64-efi --efi-directory=/boot/efi --bootloader-id=SecuBox
chroot /mnt/install update-grub

# Cleanup
umount /mnt/install/sys /mnt/install/proc /mnt/install/dev
umount /mnt/install/boot/efi
umount /mnt/install

echo ""
echo "Installation complete! Remove USB and reboot."
INSTALLER
    chmod +x "$rootfs/usr/local/bin/secubox-installer"

    ok "Disk installer added"
}

# ─────────────────────────────────────────────────────────────────────
# Data Partition (Profiles, DEBs, ISOs)
# ─────────────────────────────────────────────────────────────────────
setup_data_partition() {
    log "Setting up data partition..."

    mkdir -p "$MNT_DATA"/{profiles,debs,flash,iso,config}

    # Profile definitions
    cat > "$MNT_DATA/profiles/README.md" << 'README'
# SecuBox Profiles

## Available Profiles

### live-amd64-kiosk
Full kiosk mode with Chromium fullscreen on SecuBox dashboard.
Boot param: `secubox.profile=kiosk`

### live-amd64-vbox
VirtualBox-optimized with NAT + Host-Only networking.
Boot param: `secubox.profile=vbox`

### installer-amd64
Install SecuBox to internal disk (SSD/NVMe).
Boot param: `secubox.profile=installer`

### installer-ebin
Flash SecuBox to ESPRESSObin eMMC.
Run: `secubox-flash-emmc`

### webui (default)
Minimal boot with WebUI dashboard only.
Boot param: `secubox.profile=webui`

## Slipstreaming DEBs

Place .deb packages in /debs/ folder.
They will be installed on first boot based on profile.
README

    # Copy SecuBox .deb packages
    if [[ "$INCLUDE_DEBS" == "true" ]]; then
        log "Copying SecuBox .deb packages..."
        find "$REPO_ROOT/packages" -name "*.deb" -exec cp {} "$MNT_DATA/debs/" \; 2>/dev/null || true

        # Also check output directory
        find "$OUTPUT_DIR" -maxdepth 1 -name "secubox-*.deb" -exec cp {} "$MNT_DATA/debs/" \; 2>/dev/null || true

        local deb_count=$(find "$MNT_DATA/debs" -name "*.deb" | wc -l)
        ok "Copied $deb_count .deb packages"
    fi

    # Copy flash images
    local emmc_img="${OUTPUT_DIR}/secubox-espressobin-emmc.img"
    [[ -f "$emmc_img" ]] && cp "$emmc_img" "$MNT_DATA/flash/" && ok "eMMC flash image copied"

    ok "Data partition ready ($(du -sh "$MNT_DATA" | cut -f1))"
}

# ─────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────
main() {
    parse_args "$@"
    check_deps
    confirm_destructive

    log "═══════════════════════════════════════════════════════"
    log " SecuBox Full-Size Multi-Boot USB Builder"
    log "═══════════════════════════════════════════════════════"

    setup_target
    partition_target
    setup_loop
    format_partitions
    mount_partitions

    setup_efi_partition
    build_arm64_rootfs
    build_amd64_rootfs
    setup_data_partition

    sync

    log "═══════════════════════════════════════════════════════"
    ok "BUILD COMPLETE!"
    log ""
    log "Partition layout:"
    log "  p1 (EFI):   GRUB + U-Boot, kernels, DTBs"
    log "  p2 (ARM64): ESPRESSObin Live + eMMC flasher"
    log "  p3 (AMD64): Live + Kiosk + WebUI + Installer"
    log "  p4 (DATA):  Profiles, DEBs, flash images"
    log ""
    log "Boot modes:"
    log "  ARM64: Automatic via U-Boot"
    log "  AMD64: GRUB menu with profile selection"
    log "═══════════════════════════════════════════════════════"
}

main "$@"
