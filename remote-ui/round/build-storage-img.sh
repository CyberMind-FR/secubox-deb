#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# SecuBox Eye Remote - Build Slipstreamed Storage Image
# Creates a bootable ESPRESSObin storage.img with SecuBox modules pre-installed
#
# Usage: sudo bash build-storage-img.sh [OPTIONS]
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Defaults
SOURCE_IMG="${REPO_DIR}/board/secubox-espressobin-v7-bookworm.img.gz"
OUTPUT_IMG="${REPO_DIR}/output/eye-remote-storage.img"
DEBS_DIR="${REPO_DIR}/output/debs"
IMG_SIZE="3584M"  # 3.5GB for the storage image

RED='\033[0;31m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'
GOLD='\033[0;33m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${CYAN}[storage]${NC} $*"; }
ok()   { echo -e "${GREEN}[  OK   ]${NC} $*"; }
err()  { echo -e "${RED}[ FAIL  ]${NC} $*" >&2; exit 1; }
warn() { echo -e "${GOLD}[ WARN  ]${NC} $*"; }

usage() {
    cat << EOF
Usage: sudo $0 [OPTIONS]

Build a slipstreamed ESPRESSObin storage image for Eye Remote USB gadget.

OPTIONS:
    --source, -s PATH    Source bookworm.img.gz (default: board/secubox-espressobin-v7-bookworm.img.gz)
    --output, -o PATH    Output storage.img (default: output/eye-remote-storage.img)
    --debs, -d PATH      SecuBox .deb packages directory (default: output/debs)
    --size SIZE          Image size (default: 3584M)
    --help, -h           Show this help

EXAMPLE:
    sudo bash build-storage-img.sh
    sudo bash build-storage-img.sh --output /var/lib/secubox/eye-remote/storage.img

EOF
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --source|-s)  SOURCE_IMG="$2"; shift 2 ;;
        --output|-o)  OUTPUT_IMG="$2"; shift 2 ;;
        --debs|-d)    DEBS_DIR="$2"; shift 2 ;;
        --size)       IMG_SIZE="$2"; shift 2 ;;
        --help|-h)    usage ;;
        *) err "Unknown option: $1" ;;
    esac
done

[[ $EUID -ne 0 ]] && err "Run as root: sudo bash $0"

log "SecuBox Eye Remote Storage Image Builder"
log "========================================"
log "Source:  ${SOURCE_IMG}"
log "Output:  ${OUTPUT_IMG}"
log "Debs:    ${DEBS_DIR}"
log "Size:    ${IMG_SIZE}"

# ── Validate inputs ────────────────────────────────────────────────────────
[[ ! -f "$SOURCE_IMG" ]] && err "Source image not found: $SOURCE_IMG"
[[ ! -d "$DEBS_DIR" ]] && err "Packages directory not found: $DEBS_DIR"

# Check for QEMU
if ! command -v qemu-aarch64-static >/dev/null; then
    err "qemu-aarch64-static required. Install: apt install qemu-user-static"
fi

# Count packages
DEB_COUNT=$(find "$DEBS_DIR" -maxdepth 1 -name "secubox-*.deb" 2>/dev/null | wc -l)
[[ $DEB_COUNT -eq 0 ]] && err "No secubox-*.deb packages found in $DEBS_DIR"
log "Found ${DEB_COUNT} SecuBox packages"

# ── Setup work directory ───────────────────────────────────────────────────
WORK_DIR=$(mktemp -d /tmp/storage-build-XXXXXX)
SOURCE_MOUNT="${WORK_DIR}/source"
TARGET_MOUNT="${WORK_DIR}/target"
mkdir -p "$SOURCE_MOUNT" "$TARGET_MOUNT"

cleanup() {
    log "Cleaning up..."
    sync 2>/dev/null || true
    umount -lf "${TARGET_MOUNT}/proc" 2>/dev/null || true
    umount -lf "${TARGET_MOUNT}/sys" 2>/dev/null || true
    umount -lf "${TARGET_MOUNT}/dev" 2>/dev/null || true
    umount -lf "${SOURCE_MOUNT}" 2>/dev/null || true
    umount -lf "${TARGET_MOUNT}" 2>/dev/null || true
    [[ -n "${SOURCE_LOOP:-}" ]] && losetup -d "${SOURCE_LOOP}" 2>/dev/null || true
    [[ -n "${TARGET_LOOP:-}" ]] && losetup -d "${TARGET_LOOP}" 2>/dev/null || true
    rm -rf "${WORK_DIR}" 2>/dev/null || true
}
trap cleanup EXIT

# ── Step 1: Decompress and mount source ────────────────────────────────────
log "1/5 Preparing source image..."

SOURCE_RAW="${WORK_DIR}/source.img"
if [[ "$SOURCE_IMG" == *.gz ]]; then
    log "Decompressing ${SOURCE_IMG}..."
    gunzip -c "$SOURCE_IMG" > "$SOURCE_RAW"
else
    cp "$SOURCE_IMG" "$SOURCE_RAW"
fi

SOURCE_LOOP=$(losetup --find --show --partscan "$SOURCE_RAW")
sleep 1

# Find root partition
if [[ -b "${SOURCE_LOOP}p2" ]]; then
    SOURCE_ROOT="${SOURCE_LOOP}p2"
elif [[ -b "${SOURCE_LOOP}p1" ]]; then
    SOURCE_ROOT="${SOURCE_LOOP}p1"
else
    err "Cannot find root partition in source image"
fi

mount -o ro "$SOURCE_ROOT" "$SOURCE_MOUNT"
ok "Source mounted"

# ── Step 2: Create target image ────────────────────────────────────────────
log "2/5 Creating target image (${IMG_SIZE})..."

mkdir -p "$(dirname "$OUTPUT_IMG")"
truncate -s "$IMG_SIZE" "$OUTPUT_IMG"

# Create partitions: boot (FAT32) + root (ext4) + data (ext4)
parted -s "$OUTPUT_IMG" mklabel gpt
parted -s "$OUTPUT_IMG" mkpart boot fat32 1MiB 257MiB
parted -s "$OUTPUT_IMG" mkpart root ext4 257MiB 3000MiB
parted -s "$OUTPUT_IMG" mkpart data ext4 3000MiB 100%
parted -s "$OUTPUT_IMG" set 1 boot on

TARGET_LOOP=$(losetup --find --show --partscan "$OUTPUT_IMG")
sleep 1

# Format partitions
mkfs.fat -F32 -n BOOT "${TARGET_LOOP}p1"
mkfs.ext4 -F -L ROOT "${TARGET_LOOP}p2"
mkfs.ext4 -F -L DATA "${TARGET_LOOP}p3"

mount "${TARGET_LOOP}p2" "$TARGET_MOUNT"
ok "Target partitions created"

# ── Step 3: Copy filesystem ────────────────────────────────────────────────
log "3/5 Copying root filesystem..."

rsync -aHAXx --info=progress2 \
    --exclude '/tmp/*' \
    --exclude '/var/cache/apt/archives/*.deb' \
    --exclude '/var/lib/apt/lists/*' \
    "${SOURCE_MOUNT}/" "${TARGET_MOUNT}/"

ok "Filesystem copied"

# ── Step 4: Install SecuBox packages ───────────────────────────────────────
log "4/5 Installing SecuBox packages..."

# Copy QEMU for chroot
cp /usr/bin/qemu-aarch64-static "${TARGET_MOUNT}/usr/bin/"

# Mount for chroot
mount -t proc proc "${TARGET_MOUNT}/proc"
mount -t sysfs sysfs "${TARGET_MOUNT}/sys"
mount --bind /dev "${TARGET_MOUNT}/dev"
mount --bind /dev/pts "${TARGET_MOUNT}/dev/pts" 2>/dev/null || true

# Setup DNS for apt
cp /etc/resolv.conf "${TARGET_MOUNT}/etc/resolv.conf"

# Copy packages (filter out incompatible architectures)
DEBS_TMP="${TARGET_MOUNT}/tmp/secubox-debs"
mkdir -p "$DEBS_TMP"

# Skip list: packages with missing deps or wrong arch
SKIP_PKGS="secubox-daemon secubox-ndpid secubox-netifyd secubox-rtty"

COPIED_COUNT=0
for deb in "${DEBS_DIR}"/secubox-*.deb; do
    [[ -f "$deb" ]] || continue

    # Check architecture
    PKG_ARCH=$(dpkg-deb -f "$deb" Architecture 2>/dev/null)
    PKG_NAME=$(dpkg-deb -f "$deb" Package 2>/dev/null)

    # Skip amd64 packages on arm64 target
    [[ "$PKG_ARCH" == "amd64" ]] && continue

    # Skip known problematic packages
    echo "$SKIP_PKGS" | grep -qw "$PKG_NAME" && continue

    cp "$deb" "$DEBS_TMP/"
    COPIED_COUNT=$((COPIED_COUNT + 1))
done

log "Installing ${COPIED_COUNT} compatible packages..."

# Timeouts for QEMU chroot operations (very slow under emulation)
# Note: stdbuf doesn't work reliably with chroot, use direct timeout
CHROOT_TIMEOUT="timeout --kill-after=30s 600s"  # 10 min timeout

# Fix any interrupted dpkg state first (common after failed builds)
log "Fixing any interrupted dpkg state..."
$CHROOT_TIMEOUT chroot "${TARGET_MOUNT}" dpkg --configure -a > /tmp/dpkg-fix.log 2>&1 || true

# Update apt cache first (with timeout)
log "Updating apt cache (QEMU, may take several minutes)..."
if ! $CHROOT_TIMEOUT chroot "${TARGET_MOUNT}" apt-get update > /tmp/apt-update.log 2>&1; then
    warn "apt-get update failed or timed out (see /tmp/apt-update.log)"
    tail -5 /tmp/apt-update.log 2>/dev/null | sed 's/^/    /' || true
fi

# Install secubox-core first (with dependencies)
if ls "${DEBS_TMP}"/secubox-core_*.deb >/dev/null 2>&1; then
    log "Installing secubox-core with dependencies..."
    CORE_DEB=$(ls "${DEBS_TMP}"/secubox-core_*.deb | head -1)
    # Note: $CHROOT_TIMEOUT already includes stdbuf
    if ! $CHROOT_TIMEOUT chroot "${TARGET_MOUNT}" apt-get install -y "/tmp/secubox-debs/$(basename "$CORE_DEB")" > /tmp/core-install.log 2>&1; then
        warn "secubox-core install warnings (see /tmp/core-install.log)"
        tail -5 /tmp/core-install.log 2>/dev/null | sed 's/^/    /' || true
    fi
fi

# Install all other packages using apt (handles dependencies)
log "Installing remaining packages..."
PKG_COUNT=0
for deb in "${DEBS_TMP}"/secubox-*.deb; do
    [[ -f "$deb" ]] || continue
    PKG_NAME=$(dpkg-deb -f "$deb" Package 2>/dev/null)
    PKG_COUNT=$((PKG_COUNT + 1))

    # Skip if already installed
    if chroot "${TARGET_MOUNT}" dpkg -l "$PKG_NAME" 2>/dev/null | grep -q "^ii"; then
        continue
    fi

    log "  [$PKG_COUNT] Installing $PKG_NAME..."
    # 3 min timeout per package
    if ! timeout --kill-after=10s 180s chroot "${TARGET_MOUNT}" apt-get install -y \
        "/tmp/secubox-debs/$(basename "$deb")" > "/tmp/install-${PKG_NAME}.log" 2>&1; then
        warn "  $PKG_NAME failed (see /tmp/install-${PKG_NAME}.log)"
    fi
done

# Fix any remaining broken dependencies
log "Fixing broken dependencies..."
# Note: $CHROOT_TIMEOUT already includes stdbuf for line-buffered output
$CHROOT_TIMEOUT chroot "${TARGET_MOUNT}" apt-get -f install -y --fix-broken > /tmp/fix-broken.log 2>&1 || true

# Count installed
INSTALLED=$(chroot "${TARGET_MOUNT}" dpkg -l 2>/dev/null | grep "^ii.*secubox" | wc -l)
log "Installed ${INSTALLED} SecuBox packages"

# Add SecuBox banner/motd
cat > "${TARGET_MOUNT}/etc/motd" << 'MOTD'

  ╔═══════════════════════════════════════════════════════════════════════╗
  ║                                                                       ║
  ║   ███████╗███████╗ ██████╗██╗   ██╗██████╗  ██████╗ ██╗  ██╗         ║
  ║   ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔═══██╗╚██╗██╔╝         ║
  ║   ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║ ╚███╔╝          ║
  ║   ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║ ██╔██╗          ║
  ║   ███████║███████╗╚██████╗╚██████╔╝██████╔╝╚██████╔╝██╔╝ ██╗         ║
  ║   ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝         ║
  ║                                                                       ║
  ║           SecuBox-Deb · ESPRESSObin V7 · CyberMind                    ║
  ║                                                                       ║
  ╚═══════════════════════════════════════════════════════════════════════╝

MOTD

# Cleanup chroot
umount -lf "${TARGET_MOUNT}/dev/pts" 2>/dev/null || true
umount -lf "${TARGET_MOUNT}/proc" 2>/dev/null || true
umount -lf "${TARGET_MOUNT}/sys" 2>/dev/null || true
umount -lf "${TARGET_MOUNT}/dev" 2>/dev/null || true
rm -f "${TARGET_MOUNT}/usr/bin/qemu-aarch64-static"
rm -rf "$DEBS_TMP"

ok "SecuBox packages installed (${INSTALLED} modules)"

# ── Step 5: Configure boot ─────────────────────────────────────────────────
log "5/5 Configuring boot..."

# Mount boot partition
BOOT_MOUNT="${WORK_DIR}/boot"
mkdir -p "$BOOT_MOUNT"
mount "${TARGET_LOOP}p1" "$BOOT_MOUNT"

# Copy kernel and initramfs from target
if [[ -f "${TARGET_MOUNT}/boot/vmlinuz-"* ]]; then
    cp "${TARGET_MOUNT}/boot/vmlinuz-"* "${BOOT_MOUNT}/Image"
fi
if [[ -f "${TARGET_MOUNT}/boot/initrd.img-"* ]]; then
    cp "${TARGET_MOUNT}/boot/initrd.img-"* "${BOOT_MOUNT}/initrd.img"
fi

# Copy DTBs
mkdir -p "${BOOT_MOUNT}/dtbs/marvell"
DTB_DIR=$(find "${TARGET_MOUNT}/usr/lib" -maxdepth 2 -type d -name "marvell" -path "*/linux-image-*" 2>/dev/null | head -1)
if [[ -n "$DTB_DIR" ]] && [[ -d "$DTB_DIR" ]]; then
    cp "$DTB_DIR"/armada-3720-espressobin*.dtb "${BOOT_MOUNT}/dtbs/marvell/" 2>/dev/null || true
fi

# Create extlinux.conf for USB boot
mkdir -p "${BOOT_MOUNT}/extlinux"
cat > "${BOOT_MOUNT}/extlinux/extlinux.conf" << 'EXTLINUX'
DEFAULT secubox-usb
TIMEOUT 30
PROMPT 0

LABEL secubox-usb
    MENU LABEL SecuBox USB Boot
    KERNEL /Image
    INITRD /initrd.img
    FDT /dtbs/marvell/armada-3720-espressobin-v7-emmc.dtb
    APPEND root=/dev/sda2 rootfstype=ext4 rootwait rootdelay=10 console=ttyMV0,115200 net.ifnames=0

LABEL secubox-usb-v7
    MENU LABEL SecuBox USB Boot (V7)
    KERNEL /Image
    INITRD /initrd.img
    FDT /dtbs/marvell/armada-3720-espressobin-v7.dtb
    APPEND root=/dev/sda2 rootfstype=ext4 rootwait rootdelay=10 console=ttyMV0,115200 net.ifnames=0
EXTLINUX

# Update fstab for USB boot
cat > "${TARGET_MOUNT}/etc/fstab" << 'FSTAB'
# SecuBox Eye Remote USB Boot
/dev/sda1   /boot   vfat    defaults,noatime    0 2
/dev/sda2   /       ext4    defaults,noatime    0 1
/dev/sda3   /data   ext4    defaults,noatime    0 2
FSTAB

umount "$BOOT_MOUNT"
ok "Boot configured"

# ── Finalize ───────────────────────────────────────────────────────────────
log "Finalizing..."
sync

# Unmount
umount "${TARGET_MOUNT}"
umount "${SOURCE_MOUNT}"
losetup -d "$SOURCE_LOOP"
losetup -d "$TARGET_LOOP"
SOURCE_LOOP=""
TARGET_LOOP=""

# Calculate final size
FINAL_SIZE=$(du -h "$OUTPUT_IMG" | cut -f1)

echo ""
log "════════════════════════════════════════════════════════════════"
echo -e "${GREEN}${BOLD}Storage Image Built Successfully!${NC}"
echo ""
echo "  Image:    ${OUTPUT_IMG}"
echo "  Size:     ${FINAL_SIZE}"
echo "  Packages: ${INSTALLED} SecuBox modules"
echo ""
echo -e "  ${BOLD}Deploy to Pi Zero:${NC}"
echo "    scp ${OUTPUT_IMG} pi@<rpiz-ip>:/var/lib/secubox/eye-remote/storage.img"
echo "    ssh pi@<rpiz-ip> 'sudo systemctl restart secubox-eye-gadget'"
echo ""
echo -e "  ${BOLD}Or write directly to SD card:${NC}"
echo "    sudo dd if=${OUTPUT_IMG} of=/dev/sdX bs=4M status=progress"
echo ""
log "════════════════════════════════════════════════════════════════"
