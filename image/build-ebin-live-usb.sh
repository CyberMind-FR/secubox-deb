#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  SecuBox-DEB — build-ebin-live-usb.sh
#  Build bootable live USB for EspressoBin V7 with eMMC flasher
#  Usage: sudo bash image/build-ebin-live-usb.sh [OPTIONS]
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

# ── Version & Build Info ──────────────────────────────────────────
SECUBOX_VERSION="1.7.0"
BUILD_DATE=$(date '+%Y-%m-%d')
BUILD_TIMESTAMP=$(date '+%Y-%m-%d %H:%M')

# ── Defaults ──────────────────────────────────────────────────────
BOARD="espressobin-v7"
SUITE="bookworm"
IMG_SIZE="2G"           # USB image size
OUT_DIR="${REPO_DIR}/output"
APT_MIRROR="http://deb.debian.org/debian"
APT_SECUBOX="https://apt.secubox.in"
USE_LOCAL_CACHE=0
SLIPSTREAM_DEBS=1
EMBED_IMAGE=""          # Path to eMMC image to embed
NO_COMPRESS=0

RED='\033[0;31m'; CYAN='\033[0;36m'; GOLD='\033[0;33m'
GREEN='\033[0;32m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${CYAN}[ebin-live]${NC} $*"; }
ok()   { echo -e "${GREEN}[   OK    ]${NC} $*"; }
err()  { echo -e "${RED}[  FAIL   ]${NC} $*" >&2; exit 1; }
warn() { echo -e "${GOLD}[  WARN   ]${NC} $*"; }

# ── Parse args ────────────────────────────────────────────────────
usage() {
    cat << EOF
Usage: sudo bash build-ebin-live-usb.sh [OPTIONS]

Build a bootable live USB image for EspressoBin V7 with eMMC flasher.

OPTIONS:
    --suite SUITE       Debian suite (default: bookworm)
    --out DIR           Output directory (default: ./output)
    --size SIZE         USB image size (default: 2G)
    --embed-image PATH  Embed eMMC image for flashing (recommended)
    --local-cache       Use local APT cache (apt-cacher-ng)
    --no-slipstream     Don't include local .deb packages
    --no-compress       Skip gzip compression
    --help              Show this help

EXAMPLES:
    # Build with embedded eMMC image
    sudo bash build-ebin-live-usb.sh --embed-image output/secubox-espressobin-v7-bookworm.img.gz

    # Build without embedded image (manual flash)
    sudo bash build-ebin-live-usb.sh

OUTPUT:
    output/secubox-espressobin-v7-live-usb.img    - Raw bootable image
    output/secubox-espressobin-v7-live-usb.img.gz - Compressed image

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
        --no-slipstream)  SLIPSTREAM_DEBS=0;    shift   ;;
        --no-compress)    NO_COMPRESS=1;        shift   ;;
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
for cmd in debootstrap parted mkfs.fat mkfs.ext4 mksquashfs mkimage qemu-aarch64-static; do
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
WORK_DIR=$(mktemp -d /tmp/secubox-ebin-live-XXXXXX)
ROOTFS="${WORK_DIR}/rootfs"
LIVE_DIR="${WORK_DIR}/live"
IMG_FILE="${OUT_DIR}/secubox-espressobin-v7-live-usb.img"

log "══════════════════════════════════════════════════════════"
log "Building SecuBox Live USB for EspressoBin V7"
log "Suite       : ${SUITE}"
log "Image       : ${IMG_FILE}"
log "Size        : ${IMG_SIZE}"
log "Work dir    : ${WORK_DIR}"
if [[ -n "$EMBED_IMAGE" ]]; then
    log "Embed Image : $(basename "$EMBED_IMAGE")"
else
    log "Embed Image : None (manual flash mode)"
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
log "1/7 Debootstrap ${SUITE} arm64..."
mkdir -p "${ROOTFS}"

INCLUDE_PKGS="systemd,systemd-sysv,dbus,netplan.io,nftables,openssh-server,locales"
INCLUDE_PKGS+=",python3,python3-pip,nginx,curl,wget,ca-certificates,gnupg,console-setup"
INCLUDE_PKGS+=",iproute2,iputils-ping,ethtool,net-tools,wireguard-tools"
INCLUDE_PKGS+=",sudo,less,vim-tiny,logrotate,cron,rsync,jq,dnsmasq"
INCLUDE_PKGS+=",linux-image-arm64,live-boot,live-boot-initramfs-tools,live-config,live-config-systemd"
INCLUDE_PKGS+=",pciutils,usbutils,parted,dosfstools,lsb-release"
INCLUDE_PKGS+=",pv,dialog,fonts-terminus,kbd"

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
log "2/7 System configuration..."

# Mount for chroot
mount -t proc proc   "${ROOTFS}/proc"
mount -t sysfs sysfs "${ROOTFS}/sys"
mount --bind /dev    "${ROOTFS}/dev"

# Hostname
echo "secubox-live" > "${ROOTFS}/etc/hostname"
cat > "${ROOTFS}/etc/hosts" << 'EOF'
127.0.0.1  localhost secubox-live secubox
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

# Console font with UTF-8 box-drawing character support (Terminus)
mkdir -p "${ROOTFS}/etc/console-setup"
cat > "${ROOTFS}/etc/default/console-setup" <<EOF
ACTIVE_CONSOLES="/dev/tty[1-6]"
CHARMAP="UTF-8"
CODESET="Uni2"
FONTFACE="Terminus"
FONTSIZE="16"
EOF

# vconsole for systemd
cat > "${ROOTFS}/etc/vconsole.conf" <<EOF
KEYMAP=fr
FONT=ter-v16n
EOF

# Serial console
mkdir -p "${ROOTFS}/etc/systemd/system/serial-getty@ttyMV0.service.d"
cat > "${ROOTFS}/etc/systemd/system/serial-getty@ttyMV0.service.d/autologin.conf" << 'EOF'
[Service]
ExecStart=
ExecStart=-/sbin/agetty -o '-p -f -- \\u' --autologin root --noclear %I 115200 linux
EOF

# Enable serial console
chroot "${ROOTFS}" systemctl enable serial-getty@ttyMV0.service 2>/dev/null || true

# Network configuration
mkdir -p "${ROOTFS}/etc/netplan"
cat > "${ROOTFS}/etc/netplan/00-secubox-live.yaml" << 'NETPLAN'
network:
  version: 2
  renderer: networkd

  ethernets:
    eth0:
      dhcp4: true
      optional: true

    wan0:
      dhcp4: true
      optional: true

    lan0:
      dhcp4: false
      optional: true

    lan1:
      dhcp4: false
      optional: true

  bridges:
    br-lan:
      interfaces: []
      addresses: [192.168.1.1/24]
      dhcp4: false
      optional: true
NETPLAN

ok "Base configuration complete"

# ══════════════════════════════════════════════════════════════════
# Step 3: Install SecuBox packages
# ══════════════════════════════════════════════════════════════════
log "3/7 Installing SecuBox packages..."

# Python dependencies
chroot "${ROOTFS}" pip3 install --break-system-packages -q \
    fastapi uvicorn[standard] python-jose[cryptography] httpx \
    jinja2 tomli toml psutil pydantic 2>&1 | tail -5 || true

# Slipstream local packages if available
if [[ $SLIPSTREAM_DEBS -eq 1 ]]; then
    OUTPUT_DEBS="${REPO_DIR}/output/debs"
    CACHE_DEBS="${HOME}/.cache/secubox/debs"

    # Count available packages
    CACHE_COUNT=$(find "$CACHE_DEBS" -name "secubox-*.deb" 2>/dev/null | wc -l)
    OUTPUT_COUNT=$(ls "${OUTPUT_DEBS}"/secubox-*.deb 2>/dev/null | wc -l)
    log "Found ${CACHE_COUNT} packages in cache, ${OUTPUT_COUNT} in output/debs"

    if [[ $CACHE_COUNT -gt 0 ]] || [[ $OUTPUT_COUNT -gt 0 ]]; then
        log "Slipstreaming local packages..."
        install -d "${ROOTFS}/tmp/secubox-debs"

        # Copy from output/debs FIRST (prefer newer local builds over cache)
        if [[ -d "$OUTPUT_DEBS" ]]; then
            for deb in "${OUTPUT_DEBS}"/secubox-*.deb; do
                [[ -f "$deb" ]] || continue
                cp "$deb" "${ROOTFS}/tmp/secubox-debs/"
            done
            log "Copied ${OUTPUT_COUNT} packages from output/debs"
        fi

        # Then add from cache for packages not in output/debs
        if [[ $CACHE_COUNT -gt 0 ]]; then
            for deb in $(find "$CACHE_DEBS" -name "secubox-*.deb"); do
                pkg_name=$(basename "$deb" | sed 's/_.*$//')
                # Only copy if not already present (prefer output/debs version)
                if ! ls "${ROOTFS}/tmp/secubox-debs/${pkg_name}_"*.deb >/dev/null 2>&1; then
                    cp "$deb" "${ROOTFS}/tmp/secubox-debs/"
                    log "Added ${pkg_name} from cache"
                fi
            done
        fi

        DEB_COUNT=$(ls "${ROOTFS}/tmp/secubox-debs/"*.deb 2>/dev/null | wc -l)
        log "Installing ${DEB_COUNT} packages..."

        # Install core first (dependency for all)
        if ls "${ROOTFS}/tmp/secubox-debs/secubox-core_"*.deb >/dev/null 2>&1; then
            chroot "${ROOTFS}" bash -c 'dpkg -i --force-depends /tmp/secubox-debs/secubox-core_*.deb' || warn "secubox-core install failed"
        fi

        # Install all packages (force overwrite for duplicate files)
        chroot "${ROOTFS}" bash -c 'dpkg -i --force-depends --force-overwrite /tmp/secubox-debs/*.deb 2>&1' | \
            grep -v "^dpkg: warning" | head -30 || true

        # Fix broken dependencies
        chroot "${ROOTFS}" apt-get -f install -y --fix-broken 2>/dev/null || true

        # Verify installations
        INSTALLED_COUNT=$(chroot "${ROOTFS}" dpkg -l 'secubox-*' 2>/dev/null | grep "^ii" | wc -l)
        log "Installed ${INSTALLED_COUNT}/${DEB_COUNT} packages"

        rm -rf "${ROOTFS}/tmp/secubox-debs"
        ok "Local packages installed"
    fi
fi

ok "SecuBox packages installed"

# ══════════════════════════════════════════════════════════════════
# Step 4: Install flasher and live tools
# ══════════════════════════════════════════════════════════════════
log "4/7 Installing flasher tools..."

# Create secubox directories
mkdir -p "${ROOTFS}/secubox"
mkdir -p "${ROOTFS}/usr/sbin"
mkdir -p "${ROOTFS}/var/log"

# Install flasher script
if [[ -f "${SCRIPT_DIR}/sbin/secubox-flash-emmc" ]]; then
    cp "${SCRIPT_DIR}/sbin/secubox-flash-emmc" "${ROOTFS}/usr/sbin/"
    chmod +x "${ROOTFS}/usr/sbin/secubox-flash-emmc"
    ok "Flasher script installed"
fi

# Embed eMMC image if provided
if [[ -n "$EMBED_IMAGE" ]] && [[ -f "$EMBED_IMAGE" ]]; then
    log "Embedding eMMC image: $(basename "$EMBED_IMAGE")"
    cp "$EMBED_IMAGE" "${ROOTFS}/secubox/secubox-ebin-v7.img.gz"

    # Copy checksum if available
    CHECKSUM="${EMBED_IMAGE%.gz}.sha256"
    [[ -f "$CHECKSUM" ]] && cp "$CHECKSUM" "${ROOTFS}/secubox/"
    CHECKSUM="${EMBED_IMAGE}.sha256"
    [[ -f "$CHECKSUM" ]] && cp "$CHECKSUM" "${ROOTFS}/secubox/"

    ok "eMMC image embedded ($(du -h "${ROOTFS}/secubox/secubox-ebin-v7.img.gz" | cut -f1))"
fi

# Create auto-flash systemd service
cat > "${ROOTFS}/etc/systemd/system/secubox-autoflash.service" << 'AUTOFLASH'
[Unit]
Description=SecuBox Auto Flash to eMMC
After=multi-user.target
ConditionKernelCommandLine=secubox.autoflash=1

[Service]
Type=oneshot
ExecStart=/usr/sbin/secubox-flash-emmc --auto
StandardInput=tty
TTYPath=/dev/ttyMV0

[Install]
WantedBy=multi-user.target
AUTOFLASH

chroot "${ROOTFS}" systemctl enable secubox-autoflash.service 2>/dev/null || true

# Create welcome message for live system
cat > "${ROOTFS}/etc/motd" << 'MOTD'

  ╔═══════════════════════════════════════════════════════════════╗
  ║         SecuBox Live USB — EspressoBin V7                     ║
  ╠═══════════════════════════════════════════════════════════════╣
  ║                                                               ║
  ║  This is a LIVE system running from USB.                     ║
  ║                                                               ║
  ║  To flash SecuBox to eMMC:                                   ║
  ║    # secubox-flash-emmc                                      ║
  ║                                                               ║
  ║  Credentials: root / secubox                                 ║
  ║                                                               ║
  ╚═══════════════════════════════════════════════════════════════╝

MOTD

ok "Flasher tools installed"

# ══════════════════════════════════════════════════════════════════
# Step 5: Create SquashFS
# ══════════════════════════════════════════════════════════════════
log "5/7 Creating SquashFS filesystem..."

# Unmount before creating squashfs
umount -lf "${ROOTFS}/proc" 2>/dev/null || true
umount -lf "${ROOTFS}/sys"  2>/dev/null || true
umount -lf "${ROOTFS}/dev/pts" 2>/dev/null || true
umount -lf "${ROOTFS}/dev"  2>/dev/null || true

# Clean up rootfs
rm -rf "${ROOTFS}/tmp/"*
rm -rf "${ROOTFS}/var/cache/apt/archives/"*.deb
rm -rf "${ROOTFS}/var/lib/apt/lists/"*
rm -f "${ROOTFS}/usr/bin/qemu-aarch64-static"

# Create live directory structure
mkdir -p "${LIVE_DIR}/live"
mkdir -p "${LIVE_DIR}/boot/dtbs/marvell"
mkdir -p "${LIVE_DIR}/boot/extlinux"
mkdir -p "${LIVE_DIR}/secubox"

# Create SquashFS
mksquashfs "${ROOTFS}" "${LIVE_DIR}/live/filesystem.squashfs" \
    -comp xz -b 1M -Xdict-size 100% -no-recovery \
    -e 'var/cache/apt/archives/*' 'var/lib/apt/lists/*'

SQUASH_SIZE=$(du -h "${LIVE_DIR}/live/filesystem.squashfs" | cut -f1)
ok "SquashFS: ${SQUASH_SIZE}"

# Copy kernel and initramfs
cp "${ROOTFS}/boot/vmlinuz-"* "${LIVE_DIR}/boot/Image"
cp "${ROOTFS}/boot/initrd.img-"* "${LIVE_DIR}/boot/initrd.img"

# Copy device trees
if [[ -d "${ROOTFS}/usr/lib/linux-image-"*"/marvell" ]]; then
    cp "${ROOTFS}/usr/lib/linux-image-"*"/marvell/"* "${LIVE_DIR}/boot/dtbs/marvell/"
fi

# Copy extlinux config
if [[ -f "${REPO_DIR}/board/espressobin-v7/extlinux/extlinux.conf" ]]; then
    cp "${REPO_DIR}/board/espressobin-v7/extlinux/extlinux.conf" "${LIVE_DIR}/boot/extlinux/"
fi

# Copy boot script
if [[ -f "${REPO_DIR}/board/espressobin-v7/boot-live-usb.cmd" ]]; then
    cp "${REPO_DIR}/board/espressobin-v7/boot-live-usb.cmd" "${LIVE_DIR}/boot/"
    # Compile boot script
    if command -v mkimage >/dev/null; then
        mkimage -C none -A arm64 -T script \
            -d "${LIVE_DIR}/boot/boot-live-usb.cmd" \
            "${LIVE_DIR}/boot/boot.scr" 2>/dev/null || true
    fi
fi

# Copy U-Boot flash script (for flashing eMMC from U-Boot prompt)
if [[ -f "${REPO_DIR}/board/espressobin-v7/flash-emmc.cmd" ]]; then
    cp "${REPO_DIR}/board/espressobin-v7/flash-emmc.cmd" "${LIVE_DIR}/boot/"
    if command -v mkimage >/dev/null; then
        mkimage -C none -A arm64 -T script \
            -d "${LIVE_DIR}/boot/flash-emmc.cmd" \
            "${LIVE_DIR}/boot/flash-emmc.scr" 2>/dev/null || true
    fi
fi

# Copy embedded image to live directory (accessible at boot)
if [[ -f "${ROOTFS}/secubox/secubox-ebin-v7.img.gz" ]]; then
    cp "${ROOTFS}/secubox/"* "${LIVE_DIR}/secubox/"
fi

ok "Live filesystem prepared"

# ══════════════════════════════════════════════════════════════════
# Step 6: Create bootable image
# ══════════════════════════════════════════════════════════════════
log "6/7 Creating bootable image (${IMG_SIZE})..."

# Create raw image
truncate -s "${IMG_SIZE}" "${IMG_FILE}"

# Partition: boot (FAT32) + live (ext4)
parted -s "${IMG_FILE}" mklabel gpt
parted -s "${IMG_FILE}" mkpart boot fat32 1MiB 257MiB
parted -s "${IMG_FILE}" mkpart live ext4 257MiB 100%
parted -s "${IMG_FILE}" set 1 boot on

# Setup loop device
LOOP=$(losetup --find --show --partscan "${IMG_FILE}")
log "Loop: ${LOOP}"
sleep 1

# Format partitions
mkfs.fat -F32 -n SECUBOX "${LOOP}p1"
mkfs.ext4 -F -L live "${LOOP}p2"

# Mount and copy
mkdir -p "${WORK_DIR}/mnt/boot" "${WORK_DIR}/mnt/live"
mount "${LOOP}p1" "${WORK_DIR}/mnt/boot"
mount "${LOOP}p2" "${WORK_DIR}/mnt/live"

# Copy boot files
cp -a "${LIVE_DIR}/boot/"* "${WORK_DIR}/mnt/boot/"

# Copy embedded eMMC image to boot partition for U-Boot flash
# This allows flashing from U-Boot with: load usb 0:1 $loadaddr flash-emmc.scr && source $loadaddr
if [[ -d "${LIVE_DIR}/secubox" ]] && ls "${LIVE_DIR}/secubox/"*.img.gz >/dev/null 2>&1; then
    cp "${LIVE_DIR}/secubox/"*.img.gz "${WORK_DIR}/mnt/boot/"
    log "Embedded image copied to boot partition for U-Boot flash"
fi

# Copy live filesystem
cp -a "${LIVE_DIR}/live/"* "${WORK_DIR}/mnt/live/"
mkdir -p "${WORK_DIR}/mnt/live/secubox"
[[ -d "${LIVE_DIR}/secubox" ]] && cp -a "${LIVE_DIR}/secubox/"* "${WORK_DIR}/mnt/live/secubox/" 2>/dev/null || true

# Sync and unmount
sync
umount "${WORK_DIR}/mnt/boot"
umount "${WORK_DIR}/mnt/live"
losetup -d "${LOOP}"
LOOP=""

ok "Bootable image created"

# ══════════════════════════════════════════════════════════════════
# Step 7: Compress (optional)
# ══════════════════════════════════════════════════════════════════
if [[ $NO_COMPRESS -eq 0 ]]; then
    log "7/7 Compressing image..."
    gzip -f -k "${IMG_FILE}"
    sha256sum "${IMG_FILE}.gz" > "${IMG_FILE}.gz.sha256"
    FINAL_SIZE=$(du -h "${IMG_FILE}.gz" | cut -f1)
    ok "Compressed: ${FINAL_SIZE}"
else
    log "7/7 Skipping compression"
    sha256sum "${IMG_FILE}" > "${IMG_FILE}.sha256"
    FINAL_SIZE=$(du -h "${IMG_FILE}" | cut -f1)
fi

# ══════════════════════════════════════════════════════════════════
# Done
# ══════════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  SecuBox Live USB for EspressoBin V7 Ready!${NC}"
echo ""
echo -e "  Image: ${IMG_FILE}"
echo -e "  Size:  ${FINAL_SIZE}"
echo ""
echo -e "  ${BOLD}Flash to USB:${NC}"
echo -e "    sudo dd if=${IMG_FILE} of=/dev/sdX bs=4M status=progress"
echo ""
echo -e "  ${BOLD}Boot:${NC}"
echo -e "    1. Insert USB drive into EspressoBin"
echo -e "    2. Power on (U-Boot will auto-boot from USB)"
echo -e "    3. Serial console: 115200 8N1 (ttyMV0)"
echo ""
echo -e "  ${BOLD}Credentials:${NC}"
echo -e "    Console: root / secubox"
echo ""
echo -e "  ${BOLD}Flash to eMMC:${NC}"
echo -e "    # secubox-flash-emmc"
echo ""
echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════════════${NC}"
