#!/usr/bin/env bash
# SecuBox-Deb :: patch-multiboot-efi.sh
# Fix multiboot EFI partition with ARM64 kernel files
# CyberMind — Gérald Kerma
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[PATCH]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

usage() {
    cat <<EOF
Usage: $(basename "$0") <device>

Patch multiboot EFI partition with ARM64 kernel files.
This fixes images built before v2.2.4 that were missing kernel/DTB files.

Arguments:
    <device>    Block device (e.g., /dev/sdc) or image file

Examples:
    sudo $(basename "$0") /dev/sdc          # Patch SD card
    sudo $(basename "$0") multiboot.img     # Patch image file
EOF
    exit 0
}

[[ $# -lt 1 ]] && usage
[[ "$1" == "-h" || "$1" == "--help" ]] && usage
[[ $EUID -ne 0 ]] && err "Must run as root"

TARGET="$1"
LOOP_DEV=""
MNT_EFI=""
MNT_ROOT=""
CLEANUP_LOOP=false

cleanup() {
    log "Cleaning up..."
    [[ -n "$MNT_EFI" && -d "$MNT_EFI" ]] && { umount "$MNT_EFI" 2>/dev/null || true; rmdir "$MNT_EFI" 2>/dev/null || true; }
    [[ -n "$MNT_ROOT" && -d "$MNT_ROOT" ]] && { umount "$MNT_ROOT" 2>/dev/null || true; rmdir "$MNT_ROOT" 2>/dev/null || true; }
    [[ "$CLEANUP_LOOP" == "true" && -n "$LOOP_DEV" ]] && losetup -d "$LOOP_DEV" 2>/dev/null || true
}
trap cleanup EXIT

# Determine if target is device or file
if [[ -b "$TARGET" ]]; then
    log "Target is block device: $TARGET"
    DEVICE="$TARGET"
    # Check if it's the main device or a partition
    if [[ "$DEVICE" =~ [0-9]$ ]]; then
        err "Please specify the base device (e.g., /dev/sdc not /dev/sdc1)"
    fi
    EFI_PART="${DEVICE}1"
    ROOT_PART="${DEVICE}2"
elif [[ -f "$TARGET" ]]; then
    log "Target is image file: $TARGET"
    LOOP_DEV=$(losetup -f --show -P "$TARGET")
    CLEANUP_LOOP=true
    log "Loop device: $LOOP_DEV"
    sleep 1
    EFI_PART="${LOOP_DEV}p1"
    ROOT_PART="${LOOP_DEV}p2"
else
    err "Target not found: $TARGET"
fi

# Verify partitions exist
[[ -b "$EFI_PART" ]] || err "EFI partition not found: $EFI_PART"
[[ -b "$ROOT_PART" ]] || err "Root partition not found: $ROOT_PART"

log "EFI partition: $EFI_PART"
log "Root partition: $ROOT_PART"

# Mount partitions
MNT_EFI=$(mktemp -d)
MNT_ROOT=$(mktemp -d)

log "Mounting EFI partition..."
mount "$EFI_PART" "$MNT_EFI"

log "Mounting root partition..."
mount "$ROOT_PART" "$MNT_ROOT"

# Check current state
log "Current EFI partition contents:"
ls -la "$MNT_EFI/" || true

# Find kernel in rootfs
VMLINUZ=$(find "$MNT_ROOT/boot" -name 'vmlinuz-*' -type f 2>/dev/null | head -1)
INITRD=$(find "$MNT_ROOT/boot" -name 'initrd.img-*' -type f 2>/dev/null | head -1)

if [[ -z "$VMLINUZ" || ! -f "$VMLINUZ" ]]; then
    warn "No kernel found in rootfs /boot"
    warn "Need to install kernel first..."

    # Check if we can install kernel via chroot
    if command -v qemu-aarch64-static &>/dev/null; then
        log "Installing ARM64 kernel via chroot..."
        cp /usr/bin/qemu-aarch64-static "$MNT_ROOT/usr/bin/" 2>/dev/null || true
        chroot "$MNT_ROOT" apt-get update -qq
        chroot "$MNT_ROOT" apt-get install -y linux-image-arm64
        rm -f "$MNT_ROOT/usr/bin/qemu-aarch64-static"

        # Re-find kernel
        VMLINUZ=$(find "$MNT_ROOT/boot" -name 'vmlinuz-*' -type f 2>/dev/null | head -1)
        INITRD=$(find "$MNT_ROOT/boot" -name 'initrd.img-*' -type f 2>/dev/null | head -1)
    else
        err "No kernel in rootfs and qemu-aarch64-static not available for chroot install"
    fi
fi

log "Found kernel: $VMLINUZ"
[[ -n "$INITRD" ]] && log "Found initrd: $INITRD"

# Copy kernel as Image (U-Boot expects this name)
log "Copying kernel to EFI partition..."
cp "$VMLINUZ" "$MNT_EFI/Image"
log "  Image: $(ls -lh "$MNT_EFI/Image")"

if [[ -n "$INITRD" && -f "$INITRD" ]]; then
    cp "$INITRD" "$MNT_EFI/initrd.img"
    log "  initrd.img: $(ls -lh "$MNT_EFI/initrd.img")"
fi

# Copy DTBs
log "Copying device tree blobs..."
mkdir -p "$MNT_EFI/dtbs/marvell"

DTB_FOUND=false
for dtb_dir in "$MNT_ROOT/usr/lib/linux-image-"*"/marvell" \
               "$MNT_ROOT/boot/dtbs/"*"/marvell" \
               "$MNT_ROOT/boot/dtbs/marvell"; do
    if [[ -d "$dtb_dir" ]]; then
        log "  Source: $dtb_dir"
        cp "$dtb_dir"/armada-3720-espressobin*.dtb "$MNT_EFI/dtbs/marvell/" 2>/dev/null || true
        cp "$dtb_dir"/armada-8040-mcbin*.dtb "$MNT_EFI/dtbs/marvell/" 2>/dev/null || true
        DTB_FOUND=true
        break
    fi
done

if [[ "$DTB_FOUND" == "true" ]]; then
    log "  DTBs copied: $(ls "$MNT_EFI/dtbs/marvell/" 2>/dev/null | wc -l) files"
else
    warn "No DTB files found! Boot may fail."
fi

# Create/update boot.scr with dual boot menu
log "Creating boot.scr with dual boot menu..."

cat > /tmp/boot.cmd <<'BOOTCMD'
# SecuBox Multi-Boot U-Boot Script
# For ESPRESSObin/MOCHAbin ARM64
# Version: 2.2.4

echo ""
echo "============================================"
echo "     SecuBox Multi-Boot — ARM64"
echo "============================================"
echo ""

# Detect boot device
if test "${devtype}" = "usb"; then
    setenv bootpart "usb 0:1"
    setenv rootpart "/dev/sda2"
    setenv datapart "/dev/sda4"
    echo "Boot device: USB storage"
elif test "${devtype}" = "mmc"; then
    setenv bootpart "mmc ${devnum}:1"
    setenv rootpart "/dev/mmcblk${devnum}p2"
    setenv datapart "/dev/mmcblk${devnum}p4"
    echo "Boot device: MMC/SD"
else
    # Default to USB
    usb start
    setenv bootpart "usb 0:1"
    setenv rootpart "/dev/sda2"
    setenv datapart "/dev/sda4"
fi

# Boot menu with timeout
echo ""
echo "============================================"
echo "          BOOT MENU"
echo "============================================"
echo ""
echo "  [1] Live RAM Boot (default)"
echo "  [2] Flash SecuBox to eMMC"
echo ""
echo "Auto-boot in 5 seconds..."
echo "Press any key to select option..."
echo ""

# Set default boot option
setenv bootopt 1

# Wait for keypress with timeout (5 seconds)
if askenv -t 5 bootopt "Select option [1-2]: "; then
    echo "Selected: ${bootopt}"
else
    echo "Timeout - using default (Live Boot)"
    setenv bootopt 1
fi

# Handle boot options
if test "${bootopt}" = "2"; then
    echo ""
    echo "============================================"
    echo "     eMMC FLASH MODE"
    echo "============================================"
    echo ""
    echo "WARNING: This will erase ALL data on eMMC!"
    echo ""
    echo "After boot, run: secubox-flash-emmc"
    echo ""
    setenv bootargs_extra "secubox.flash_mode=1"
else
    echo ""
    echo "============================================"
    echo "     LIVE RAM BOOT"
    echo "============================================"
    echo ""
    setenv bootargs_extra ""
fi

# Load kernel
echo "Loading ARM64 kernel..."
if load ${bootpart} ${kernel_addr_r} Image; then
    echo "Kernel loaded successfully"
else
    echo "ERROR: Failed to load kernel!"
    echo "Check that Image exists on EFI partition"
    sleep 10
    reset
fi

# Load device tree
echo "Loading device tree..."
if load ${bootpart} ${fdt_addr_r} dtbs/marvell/armada-3720-espressobin-v7-emmc.dtb; then
    echo "Loaded ESPRESSObin v7 eMMC DTB"
elif load ${bootpart} ${fdt_addr_r} dtbs/marvell/armada-3720-espressobin-v7.dtb; then
    echo "Loaded ESPRESSObin v7 DTB"
elif load ${bootpart} ${fdt_addr_r} dtbs/marvell/armada-3720-espressobin.dtb; then
    echo "Loaded ESPRESSObin DTB"
else
    echo "ERROR: No compatible DTB found!"
    sleep 10
    reset
fi

# Load initramfs
echo "Loading initramfs..."
if load ${bootpart} ${ramdisk_addr_r} initrd.img; then
    setenv initrd_size ${filesize}
    setenv use_initrd 1
    echo "Initramfs loaded (${filesize} bytes)"
else
    setenv use_initrd 0
    echo "No initramfs - direct boot"
fi

# Boot arguments
setenv bootargs "root=${rootpart} rootfstype=ext4 rootwait rootdelay=5 console=ttyMV0,115200 net.ifnames=0 secubox.data=${datapart} ${bootargs_extra}"

echo ""
echo "Booting SecuBox ARM64..."
echo "============================================"
echo ""

if test "${use_initrd}" = "1"; then
    booti ${kernel_addr_r} ${ramdisk_addr_r}:${initrd_size} ${fdt_addr_r}
else
    booti ${kernel_addr_r} - ${fdt_addr_r}
fi
BOOTCMD

if command -v mkimage &>/dev/null; then
    mkimage -A arm64 -T script -C none -d /tmp/boot.cmd "$MNT_EFI/boot.scr"
    log "  boot.scr compiled"
else
    cp /tmp/boot.cmd "$MNT_EFI/boot.cmd"
    warn "mkimage not found, copied as boot.cmd (may need manual conversion)"
fi

# Verify final state
echo ""
log "=== Patch Complete ==="
log "EFI partition contents:"
ls -lh "$MNT_EFI/"
echo ""
log "DTBs:"
ls -lh "$MNT_EFI/dtbs/marvell/" 2>/dev/null || echo "  (none)"
echo ""
log "Ready to test!"
