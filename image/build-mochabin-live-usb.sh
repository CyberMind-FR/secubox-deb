#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  SecuBox-DEB — build-mochabin-live-usb.sh v1.0
#  Build bootable live USB for MOCHAbin with LED kernel support
#  Usage: sudo bash image/build-mochabin-live-usb.sh [OPTIONS]
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

# ── Version & Build Info ──────────────────────────────────────────
SECUBOX_VERSION="2.0.0"
BUILD_DATE=$(date '+%Y-%m-%d')
BUILD_TIMESTAMP=$(date '+%Y-%m-%d %H:%M')

# ── Defaults ──────────────────────────────────────────────────────
BOARD="mochabin"
SUITE="bookworm"
IMG_SIZE="4G"           # USB image size
OUT_DIR="${REPO_DIR}/output"
APT_MIRROR="http://deb.debian.org/debian"
APT_SECUBOX="https://apt.secubox.in"
USE_LOCAL_CACHE=0
SLIPSTREAM_DEBS=1
EMBED_IMAGE=""          # Path to eMMC image to embed
NO_COMPRESS=0
INCLUDE_LED_KERNEL=1    # Include LED-enabled kernel
INCLUDE_RECOVERY=1      # Include recovery tools

RED='\033[0;31m'; CYAN='\033[0;36m'; GOLD='\033[0;33m'
GREEN='\033[0;32m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${CYAN}[mochabin]${NC} $*"; }
ok()   { echo -e "${GREEN}[   OK    ]${NC} $*"; }
err()  { echo -e "${RED}[  FAIL   ]${NC} $*" >&2; exit 1; }
warn() { echo -e "${GOLD}[  WARN   ]${NC} $*"; }

# ── Parse args ────────────────────────────────────────────────────
usage() {
    cat << EOF
Usage: sudo bash build-mochabin-live-usb.sh [OPTIONS]

Build a bootable live USB image for MOCHAbin (Armada 7040) with:
- LED heartbeat support (IS31FL3199)
- Recovery tools for board recovery
- All SecuBox packages slipstreamed

OPTIONS:
    --suite SUITE       Debian suite (default: bookworm)
    --out DIR           Output directory (default: ./output)
    --size SIZE         USB image size (default: 4G)
    --embed-image PATH  Embed eMMC image for flashing (optional)
    --local-cache       Use local APT cache (apt-cacher-ng)
    --no-slipstream     Don't include local .deb packages
    --no-compress       Skip gzip compression
    --no-led            Don't include LED-enabled kernel
    --no-recovery       Don't include recovery tools
    --help              Show this help

FEATURES:
    - Tow-Boot / U-Boot distroboot compatible
    - LED kernel with IS31FL3199 driver
    - Serial console on ttyS0 @ 115200
    - Recovery tools for kwboot/XMODEM
    - Network: 10GbE RJ45 + SFP+ + 4× GbE

EXAMPLES:
    # Build with LED kernel and recovery
    sudo bash build-mochabin-live-usb.sh

    # Build with embedded eMMC image
    sudo bash build-mochabin-live-usb.sh --embed-image output/secubox-mochabin.img.gz

OUTPUT:
    output/secubox-mochabin-live-usb.img    - Raw bootable image
    output/secubox-mochabin-live-usb.img.gz - Compressed image

FLASH:
    zcat output/secubox-mochabin-live-usb.img.gz | sudo dd of=/dev/sdX bs=4M status=progress

EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --suite)          SUITE="$2";           shift 2 ;;
        --out)            OUT_DIR="$2";         shift 2 ;;
        --size)           IMG_SIZE="$2";        shift 2 ;;
        --embed-image)    EMBED_IMAGE="$2";     shift 2 ;;
        --local-cache)    USE_LOCAL_CACHE=1;    shift   ;;
        --slipstream)     SLIPSTREAM_DEBS=1;    shift   ;;
        --no-slipstream)  SLIPSTREAM_DEBS=0;    shift   ;;
        --no-compress)    NO_COMPRESS=1;        shift   ;;
        --no-led)         INCLUDE_LED_KERNEL=0; shift   ;;
        --no-recovery)    INCLUDE_RECOVERY=0;   shift   ;;
        --help|-h)        usage ;;
        *) err "Unknown argument: $1" ;;
    esac
done

# ── Checks ────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && err "This script must be run as root (sudo)"

# Check for embedded image
if [[ -n "$EMBED_IMAGE" ]] && [[ ! -f "$EMBED_IMAGE" ]]; then
    err "Embedded image not found: $EMBED_IMAGE"
fi

# Required tools
log "Checking dependencies..."
for cmd in debootstrap parted mkfs.fat mkfs.ext4 mksquashfs qemu-aarch64-static; do
    command -v "$cmd" >/dev/null || {
        warn "Missing: $cmd"
        apt-get install -y -qq debootstrap squashfs-tools u-boot-tools qemu-user-static parted dosfstools 2>/dev/null || true
    }
done

# Check again after install
for cmd in debootstrap parted mkfs.fat mkfs.ext4 mksquashfs; do
    command -v "$cmd" >/dev/null || err "Missing required tool: $cmd"
done

# ── Local cache detection ─────────────────────────────────────
if [[ $USE_LOCAL_CACHE -eq 1 ]]; then
    if curl -sf "http://127.0.0.1:3142" >/dev/null 2>&1; then
        APT_MIRROR="http://127.0.0.1:3142/deb.debian.org/debian"
        log "Using apt-cacher-ng"
    fi
    if curl -sf "http://127.0.0.1:8080/dists/${SUITE}/Release" >/dev/null 2>&1; then
        APT_SECUBOX="http://127.0.0.1:8080"
        log "Using local SecuBox repo"
    fi
fi

# ── Setup ─────────────────────────────────────────────────────────
mkdir -p "$OUT_DIR"
WORK_DIR=$(mktemp -d /tmp/secubox-mochabin-live-XXXXXX)
ROOTFS="${WORK_DIR}/rootfs"
BOOT_DIR="${WORK_DIR}/boot"
IMG_FILE="${OUT_DIR}/secubox-mochabin-live-usb.img"

log "══════════════════════════════════════════════════════════"
log "Building SecuBox Live USB for MOCHAbin (Armada 7040)"
log "Suite       : ${SUITE}"
log "Image       : ${IMG_FILE}"
log "Size        : ${IMG_SIZE}"
log "Work dir    : ${WORK_DIR}"
log "LED kernel  : $([[ $INCLUDE_LED_KERNEL -eq 1 ]] && echo "yes" || echo "no")"
log "Recovery    : $([[ $INCLUDE_RECOVERY -eq 1 ]] && echo "yes" || echo "no")"
if [[ -n "$EMBED_IMAGE" ]]; then
    log "Embed Image : $(basename "$EMBED_IMAGE")"
fi
log "══════════════════════════════════════════════════════════"

cleanup() {
    log "Cleaning up..."
    umount -lf "${ROOTFS}/proc" 2>/dev/null || true
    umount -lf "${ROOTFS}/sys"  2>/dev/null || true
    umount -lf "${ROOTFS}/dev/pts" 2>/dev/null || true
    umount -lf "${ROOTFS}/dev"  2>/dev/null || true
    umount -lf "${WORK_DIR}/mnt/"* 2>/dev/null || true
    [[ -n "${LOOP:-}" ]] && losetup -d "${LOOP}" 2>/dev/null || true
    if ! mount | grep -q "${WORK_DIR}"; then
        rm -rf "${WORK_DIR}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# ══════════════════════════════════════════════════════════════════
# Step 1: Debootstrap ARM64
# ══════════════════════════════════════════════════════════════════
log "1/8 Debootstrap ${SUITE} arm64..."
mkdir -p "${ROOTFS}"

# Core system packages
INCLUDE_PKGS="systemd,systemd-sysv,dbus,netplan.io,nftables,openssh-server,locales"
INCLUDE_PKGS+=",python3,python3-pip,nginx,curl,wget,ca-certificates,gnupg,console-setup"
INCLUDE_PKGS+=",iproute2,iputils-ping,ethtool,net-tools,wireguard-tools,iw,hostapd,wpasupplicant"
INCLUDE_PKGS+=",sudo,less,vim-tiny,logrotate,cron,rsync,jq,dnsmasq"
INCLUDE_PKGS+=",linux-image-arm64,live-boot,live-boot-initramfs-tools,live-config,live-config-systemd"
INCLUDE_PKGS+=",pciutils,usbutils,parted,dosfstools,e2fsprogs,lsb-release,gdisk"
INCLUDE_PKGS+=",pv,dialog,fonts-terminus,kbd,i2c-tools"

# Python dependencies for SecuBox modules
INCLUDE_PKGS+=",python3-fastapi,python3-uvicorn,python3-httpx,python3-psutil"
INCLUDE_PKGS+=",python3-aiosqlite,python3-jinja2,python3-jwt"
INCLUDE_PKGS+=",python3-aiofiles,python3-pil,python3-tomli,python3-pydantic"
INCLUDE_PKGS+=",python3-toml,python3-netifaces,python3-serial"

# Network and security tools
INCLUDE_PKGS+=",bridge-utils,dnsutils,iputils-arping,avahi-daemon,avahi-utils"
INCLUDE_PKGS+=",ieee-data,procps,openssl,haproxy,qrencode"
INCLUDE_PKGS+=",fonts-noto-color-emoji"

# WiFi firmware + regulatory (CM-MESH-MPCIE-2026-06 v0.2.1)
#   firmware-misc-nonfree : mt7662 (MT7632U) + ath10k (QCA9880) blobs
#   firmware-atheros      : htc_9271.fw (AR9271 USB) — firmware-free option
#   wireless-regdb        : signed regulatory DB, FR domain lock at postinst
INCLUDE_PKGS+=",firmware-misc-nonfree,firmware-atheros,wireless-regdb"

# Cross-architecture debootstrap with QEMU
debootstrap --arch=arm64 --foreign --include="${INCLUDE_PKGS}" \
    "${SUITE}" "${ROOTFS}" "${APT_MIRROR}"

# Copy QEMU static binary for chroot
cp /usr/bin/qemu-aarch64-static "${ROOTFS}/usr/bin/"

# Complete second stage
chroot "${ROOTFS}" /debootstrap/debootstrap --second-stage

ok "Debootstrap complete"

# ══════════════════════════════════════════════════════════════════
# Step 2: Base configuration
# ══════════════════════════════════════════════════════════════════
log "2/8 System configuration..."

# Mount for chroot
mount -t proc proc   "${ROOTFS}/proc"
mount -t sysfs sysfs "${ROOTFS}/sys"
mount --bind /dev    "${ROOTFS}/dev"

# Configure APT sources
cat > "${ROOTFS}/etc/apt/sources.list" << SOURCES
deb ${APT_MIRROR} ${SUITE} main contrib non-free non-free-firmware
deb ${APT_MIRROR} ${SUITE}-updates main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security ${SUITE}-security main contrib non-free non-free-firmware
SOURCES

# Update and install critical packages
log "Installing critical packages..."
chroot "${ROOTFS}" bash -c "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
    parted e2fsprogs dosfstools gdisk rsync findutils \
    iproute2 iputils-ping net-tools bridge-utils \
    systemd-resolved netplan.io device-tree-compiler \
    2>&1" | tail -20 || warn "Some packages may have failed"

# Python crypto packages
chroot "${ROOTFS}" bash -c "DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
    python3-cryptography python3-jose python3-zmq 2>&1" | tail -10 || warn "Some Python packages not installed"

# Hostname
echo "secubox-mochabin" > "${ROOTFS}/etc/hostname"
cat > "${ROOTFS}/etc/hosts" << 'EOF'
127.0.0.1  localhost secubox-mochabin secubox
::1        localhost ip6-localhost ip6-loopback
EOF

# Root password: secubox
chroot "${ROOTFS}" bash -c 'echo "root:secubox" | chpasswd'

# Timezone
echo "Europe/Paris" > "${ROOTFS}/etc/timezone"
chroot "${ROOTFS}" dpkg-reconfigure -f noninteractive tzdata 2>/dev/null || true

# Locale
chroot "${ROOTFS}" bash -c "locale-gen en_US.UTF-8 fr_FR.UTF-8 || true"
echo 'LANG=fr_FR.UTF-8' > "${ROOTFS}/etc/default/locale"

# Console font
mkdir -p "${ROOTFS}/etc/console-setup"
cat > "${ROOTFS}/etc/default/console-setup" <<EOF
ACTIVE_CONSOLES="/dev/tty[1-6]"
CHARMAP="UTF-8"
CODESET="Uni2"
FONTFACE="Terminus"
FONTSIZE="16"
EOF

cat > "${ROOTFS}/etc/vconsole.conf" <<EOF
KEYMAP=fr
FONT=ter-v16n
EOF

# Serial console on ttyS0 (MOCHAbin uses ttyS0)
mkdir -p "${ROOTFS}/etc/systemd/system/serial-getty@ttyS0.service.d"
cat > "${ROOTFS}/etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf" << 'EOF'
[Service]
ExecStart=
ExecStart=-/sbin/agetty -o '-p -f -- \\u' --autologin root --noclear %I 115200 linux
EOF

chroot "${ROOTFS}" systemctl enable serial-getty@ttyS0.service 2>/dev/null || true

ok "Base configuration complete"

# ══════════════════════════════════════════════════════════════════
# Step 3: Network configuration (MOCHAbin specific)
# ══════════════════════════════════════════════════════════════════
log "3/8 Network configuration..."

mkdir -p "${ROOTFS}/etc/netplan"
cat > "${ROOTFS}/etc/netplan/00-secubox-mochabin.yaml" << 'NETPLAN'
# MOCHAbin Network Configuration
# Interfaces: eth0 (10G RJ45), eth1-4 (GbE), eth5-6 (SFP+)
network:
  version: 2
  renderer: networkd

  ethernets:
    # 10G RJ45 WAN
    eth0:
      dhcp4: true
      dhcp6: false
      optional: true

    # GbE LAN ports (bridged)
    eth1:
      dhcp4: false
      optional: true
    eth2:
      dhcp4: false
      optional: true
    eth3:
      dhcp4: false
      optional: true
    eth4:
      dhcp4: false
      optional: true

    # SFP+ ports (optional)
    eth5:
      dhcp4: false
      optional: true
    eth6:
      dhcp4: false
      optional: true

  bridges:
    br-lan:
      interfaces: [eth1, eth2, eth3, eth4]
      addresses: [192.168.10.1/24]
      dhcp4: false
      parameters:
        stp: false
        forward-delay: 0
NETPLAN

ok "Network configured"

# ══════════════════════════════════════════════════════════════════
# Step 4: LED kernel and heartbeat
# ══════════════════════════════════════════════════════════════════
if [[ $INCLUDE_LED_KERNEL -eq 1 ]]; then
    log "4/8 Installing LED support..."

    # Copy LED DTS overlay
    LED_DTS="${REPO_DIR}/packages/secubox-led-heartbeat/boot/overlays/secubox-leds.dts"
    if [[ -f "$LED_DTS" ]]; then
        mkdir -p "${ROOTFS}/usr/share/secubox/overlays"
        cp "$LED_DTS" "${ROOTFS}/usr/share/secubox/overlays/"
    fi

    # Copy LED heartbeat script
    LED_SCRIPT="${REPO_DIR}/packages/secubox-led-heartbeat/usr/sbin/secubox-led-heartbeat-bash"
    if [[ -f "$LED_SCRIPT" ]]; then
        cp "$LED_SCRIPT" "${ROOTFS}/usr/sbin/secubox-led-heartbeat"
        chmod +x "${ROOTFS}/usr/sbin/secubox-led-heartbeat"
    fi

    # LED config
    mkdir -p "${ROOTFS}/etc/secubox"
    cat > "${ROOTFS}/etc/secubox/leds.toml" << 'TOML'
# SecuBox LED Configuration
# MOCHAbin IS31FL3199 LED controller

[general]
enabled = true
i2c_bus = 1
i2c_addr = 0x64
gpio_sdb = 94

[health]
led = 1
green_threshold = 80
yellow_threshold = 50

[security]
led = 2
# Indicates firewall/IDS status

[capacity]
led = 3
# Shows disk/memory usage
TOML

    # LED module load
    mkdir -p "${ROOTFS}/etc/modules-load.d"
    cat > "${ROOTFS}/etc/modules-load.d/secubox-leds.conf" << 'EOF'
# SecuBox LED drivers
leds_is31fl319x
ledtrig-heartbeat
i2c-mv64xxx
EOF

    # LED systemd service
    mkdir -p "${ROOTFS}/etc/systemd/system"
    cat > "${ROOTFS}/etc/systemd/system/secubox-led-heartbeat.service" << 'SERVICE'
[Unit]
Description=SecuBox LED Heartbeat
After=local-fs.target
Wants=local-fs.target

[Service]
Type=simple
ExecStart=/usr/sbin/secubox-led-heartbeat
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE

    chroot "${ROOTFS}" systemctl enable secubox-led-heartbeat.service 2>/dev/null || true
    ok "LED support installed"
else
    log "4/8 Skipping LED support (--no-led)"
fi

# ══════════════════════════════════════════════════════════════════
# Step 5: Recovery tools
# ══════════════════════════════════════════════════════════════════
if [[ $INCLUDE_RECOVERY -eq 1 ]]; then
    log "5/8 Installing recovery tools..."

    mkdir -p "${ROOTFS}/srv/secubox-recovery/boards/mochabin"
    mkdir -p "${ROOTFS}/srv/secubox-recovery/tools"

    # Recovery info
    cat > "${ROOTFS}/srv/secubox-recovery/boards/mochabin/info.json" << 'JSON'
{
    "board": "MOCHAbin",
    "soc": "Armada 7040",
    "cores": 4,
    "arch": "cortex-a72",
    "boot_tool": "mvebu64boot",
    "uart": "/dev/ttyUSB0",
    "baud": 115200,
    "storage": ["emmc", "sata", "usb"],
    "led_driver": "is31fl319x",
    "led_i2c": "1-0064"
}
JSON

    # Diagnostic script
    cat > "${ROOTFS}/usr/sbin/secubox-diag" << 'DIAG'
#!/bin/bash
# SecuBox MOCHAbin Diagnostic Script
set -euo pipefail

echo "═══════════════════════════════════════════════════════"
echo "SecuBox MOCHAbin Diagnostics"
echo "═══════════════════════════════════════════════════════"

echo -e "\n── System ──"
uname -a
cat /etc/os-release | grep PRETTY_NAME

echo -e "\n── Hardware ──"
cat /proc/cpuinfo | grep -E "^(model name|Hardware)" | head -2
free -h | grep Mem

echo -e "\n── Network Interfaces ──"
ip -br link show

echo -e "\n── I2C Devices ──"
for bus in /dev/i2c-*; do
    if [[ -e "$bus" ]]; then
        echo "Bus: $bus"
        i2cdetect -y "${bus##*-}" 2>/dev/null || echo "  (scan failed)"
    fi
done

echo -e "\n── LED Status ──"
if [[ -d /sys/class/leds ]]; then
    for led in /sys/class/leds/*/brightness; do
        name=$(dirname "$led" | xargs basename)
        val=$(cat "$led" 2>/dev/null || echo "?")
        echo "  $name: $val"
    done
else
    echo "  No LEDs found"
fi

echo -e "\n── Storage ──"
lsblk -o NAME,SIZE,TYPE,MOUNTPOINT 2>/dev/null || fdisk -l 2>/dev/null | head -20

echo "═══════════════════════════════════════════════════════"
DIAG
    chmod +x "${ROOTFS}/usr/sbin/secubox-diag"

    ok "Recovery tools installed"
else
    log "5/8 Skipping recovery tools (--no-recovery)"
fi

# ══════════════════════════════════════════════════════════════════
# Step 6: Slipstream SecuBox packages
# ══════════════════════════════════════════════════════════════════
if [[ $SLIPSTREAM_DEBS -eq 1 ]]; then
    log "6/8 Slipstreaming SecuBox packages..."

    DEBS_DIR="${OUT_DIR}/debs"
    if [[ -d "$DEBS_DIR" ]] && compgen -G "${DEBS_DIR}/*.deb" > /dev/null; then
        mkdir -p "${ROOTFS}/tmp/debs"
        cp "${DEBS_DIR}"/*.deb "${ROOTFS}/tmp/debs/" 2>/dev/null || true
        DEB_COUNT=$(ls -1 "${ROOTFS}/tmp/debs/"*.deb 2>/dev/null | wc -l)
        log "Found $DEB_COUNT .deb packages"

        chroot "${ROOTFS}" bash -c "dpkg -i /tmp/debs/*.deb 2>/dev/null || apt-get -f install -y" || warn "Some packages failed"
        rm -rf "${ROOTFS}/tmp/debs"
        ok "Packages slipstreamed"
    else
        warn "No .deb packages found in $DEBS_DIR"
    fi
else
    log "6/8 Skipping package slipstream (--no-slipstream)"
fi

# ══════════════════════════════════════════════════════════════════
# Step 7: Create image
# ══════════════════════════════════════════════════════════════════
log "7/8 Creating bootable image..."

# Cleanup chroot mounts before image creation
umount -lf "${ROOTFS}/proc" 2>/dev/null || true
umount -lf "${ROOTFS}/sys"  2>/dev/null || true
umount -lf "${ROOTFS}/dev"  2>/dev/null || true

# Create disk image
truncate -s "$IMG_SIZE" "$IMG_FILE"
LOOP=$(losetup -f --show "$IMG_FILE")

# Partition: ESP (128M) + rootfs (rest)
parted -s "$LOOP" mklabel gpt
parted -s "$LOOP" mkpart ESP fat32 1MiB 129MiB
parted -s "$LOOP" set 1 esp on
parted -s "$LOOP" mkpart rootfs ext4 129MiB 100%

# Rescan partitions
partprobe "$LOOP"
sleep 1

# Get partition devices
ESP_PART="${LOOP}p1"
ROOT_PART="${LOOP}p2"

# Fallback for different naming
[[ -b "$ESP_PART" ]] || ESP_PART="${LOOP}p1"
[[ -b "$ROOT_PART" ]] || ROOT_PART="${LOOP}p2"

# Format
mkfs.fat -F 32 -n ESP "$ESP_PART"
mkfs.ext4 -L rootfs -F "$ROOT_PART"

# Mount and copy
mkdir -p "${WORK_DIR}/mnt/rootfs" "${WORK_DIR}/mnt/esp"
mount "$ROOT_PART" "${WORK_DIR}/mnt/rootfs"
mount "$ESP_PART" "${WORK_DIR}/mnt/esp"

# Copy rootfs
rsync -aHAX --info=progress2 "${ROOTFS}/" "${WORK_DIR}/mnt/rootfs/"

# Setup boot partition
mkdir -p "${WORK_DIR}/mnt/esp/extlinux"

# Copy MOCHAbin extlinux config
EXTLINUX_CONF="${REPO_DIR}/board/mochabin/extlinux/extlinux.conf"
if [[ -f "$EXTLINUX_CONF" ]]; then
    cp "$EXTLINUX_CONF" "${WORK_DIR}/mnt/esp/extlinux/"
    # Adjust for USB boot (root=/dev/sda2 or UUID)
    ROOT_UUID=$(blkid -s UUID -o value "$ROOT_PART")
    sed -i "s|root=/dev/mmcblk0p2|root=UUID=${ROOT_UUID}|g" "${WORK_DIR}/mnt/esp/extlinux/extlinux.conf"
fi

# Copy kernel and DTB to ESP
KERNEL_SRC="${WORK_DIR}/mnt/rootfs/boot"
if [[ -f "${KERNEL_SRC}/vmlinuz" ]]; then
    cp "${KERNEL_SRC}/vmlinuz" "${WORK_DIR}/mnt/esp/Image"
fi
if [[ -f "${KERNEL_SRC}/initrd.img" ]]; then
    cp "${KERNEL_SRC}/initrd.img" "${WORK_DIR}/mnt/esp/"
fi

# Copy DTB
mkdir -p "${WORK_DIR}/mnt/esp/dtbs/marvell"
if [[ -d "${KERNEL_SRC}/dtbs" ]]; then
    cp -r "${KERNEL_SRC}/dtbs/"* "${WORK_DIR}/mnt/esp/dtbs/" 2>/dev/null || true
fi
# Try standard Debian location
if [[ -d "${WORK_DIR}/mnt/rootfs/usr/lib/linux-image-"* ]]; then
    DTB_DIR=$(ls -1d "${WORK_DIR}/mnt/rootfs/usr/lib/linux-image-"* | head -1)
    if [[ -f "${DTB_DIR}/marvell/armada-7040-mochabin.dtb" ]]; then
        cp "${DTB_DIR}/marvell/armada-7040-mochabin.dtb" "${WORK_DIR}/mnt/esp/dtbs/marvell/"
    fi
fi

# Create fstab
cat > "${WORK_DIR}/mnt/rootfs/etc/fstab" << FSTAB
# SecuBox MOCHAbin Live USB
UUID=${ROOT_UUID}  /     ext4  errors=remount-ro  0  1
LABEL=ESP          /boot vfat  defaults           0  2
FSTAB

# Unmount
sync
umount "${WORK_DIR}/mnt/esp"
umount "${WORK_DIR}/mnt/rootfs"
losetup -d "$LOOP"
LOOP=""

ok "Image created: $IMG_FILE"

# ══════════════════════════════════════════════════════════════════
# Step 8: Compress
# ══════════════════════════════════════════════════════════════════
if [[ $NO_COMPRESS -eq 0 ]]; then
    log "8/8 Compressing image..."
    gzip -f -k "$IMG_FILE"
    ok "Compressed: ${IMG_FILE}.gz"
else
    log "8/8 Skipping compression (--no-compress)"
fi

# ══════════════════════════════════════════════════════════════════
# Done
# ══════════════════════════════════════════════════════════════════
IMG_SIZE_MB=$(du -m "$IMG_FILE" | cut -f1)
log ""
log "══════════════════════════════════════════════════════════"
log "Build complete!"
log "══════════════════════════════════════════════════════════"
log "Image       : $IMG_FILE ($IMG_SIZE_MB MB)"
[[ $NO_COMPRESS -eq 0 ]] && log "Compressed  : ${IMG_FILE}.gz"
log ""
log "Flash to USB:"
log "  zcat ${IMG_FILE}.gz | sudo dd of=/dev/sdX bs=4M status=progress"
log ""
log "Boot:"
log "  1. Insert USB into MOCHAbin"
log "  2. Enter U-Boot prompt"
log "  3. run usb_boot  (or: usb start; load usb 0:1 ...)"
log ""
log "Default credentials:"
log "  User: root"
log "  Pass: secubox"
log "══════════════════════════════════════════════════════════"
