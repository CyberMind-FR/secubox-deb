#!/usr/bin/env bash
# SecuBox Multi-Boot Storage Builder
# Creates bootable image for ARM64 + AMD64 with shared data
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT_DIR="${REPO_ROOT}/output"
CACHE_DIR="${REPO_ROOT}/cache"

# Defaults
IMAGE_SIZE="16G"
OUTPUT_FILE=""
ARM64_ROOTFS=""
AMD64_ROOTFS=""
EMMC_IMAGE=""
INCLUDE_EMMC=true
VERBOSE=false

# Partition sizes (in MB)
EFI_SIZE=512
ARM64_SIZE=3072
AMD64_SIZE=3072
# DATA_SIZE = remaining space

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Build SecuBox multi-boot storage image (ARM64 + AMD64 + Shared Data)

Options:
    -s, --size SIZE         Image size (default: 16G)
    -o, --output FILE       Output image file
    --arm64-rootfs DIR      ARM64 rootfs directory
    --amd64-rootfs DIR      AMD64 rootfs directory
    --emmc-image FILE       eMMC image to include for flashing
    --no-emmc               Don't include eMMC flasher image
    -v, --verbose           Verbose output
    -h, --help              Show this help

Examples:
    $(basename "$0") -s 16G -o multiboot.img
    $(basename "$0") --arm64-rootfs /path/to/arm64 --amd64-rootfs /path/to/amd64
EOF
    exit 0
}

log() { echo "[$(date '+%H:%M:%S')] $*"; }
err() { echo "[ERROR] $*" >&2; exit 1; }

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -s|--size) IMAGE_SIZE="$2"; shift 2 ;;
            -o|--output) OUTPUT_FILE="$2"; shift 2 ;;
            --arm64-rootfs) ARM64_ROOTFS="$2"; shift 2 ;;
            --amd64-rootfs) AMD64_ROOTFS="$2"; shift 2 ;;
            --emmc-image) EMMC_IMAGE="$2"; shift 2 ;;
            --no-emmc) INCLUDE_EMMC=false; shift ;;
            -v|--verbose) VERBOSE=true; shift ;;
            -h|--help) usage ;;
            *) err "Unknown option: $1" ;;
        esac
    done

    [[ -z "$OUTPUT_FILE" ]] && OUTPUT_FILE="${OUTPUT_DIR}/secubox-multiboot-$(date +%Y%m%d).img"
}

check_deps() {
    local deps=(parted mkfs.vfat mkfs.ext4 debootstrap grub-mkimage losetup)
    for cmd in "${deps[@]}"; do
        command -v "$cmd" &>/dev/null || err "Missing: $cmd"
    done
    [[ $EUID -eq 0 ]] || err "Must run as root"
}

create_image() {
    log "Creating ${IMAGE_SIZE} image: ${OUTPUT_FILE}"
    mkdir -p "$(dirname "$OUTPUT_FILE")"
    truncate -s "$IMAGE_SIZE" "$OUTPUT_FILE"
}

partition_image() {
    log "Partitioning image..."

    parted -s "$OUTPUT_FILE" mklabel gpt

    local start=1
    local end=$((start + EFI_SIZE))

    # Partition 1: EFI System Partition
    parted -s "$OUTPUT_FILE" mkpart ESP fat32 ${start}MiB ${end}MiB
    parted -s "$OUTPUT_FILE" set 1 esp on
    parted -s "$OUTPUT_FILE" set 1 boot on
    start=$end
    end=$((start + ARM64_SIZE))

    # Partition 2: ARM64 rootfs
    parted -s "$OUTPUT_FILE" mkpart arm64-root ext4 ${start}MiB ${end}MiB
    start=$end
    end=$((start + AMD64_SIZE))

    # Partition 3: AMD64 rootfs
    parted -s "$OUTPUT_FILE" mkpart amd64-root ext4 ${start}MiB ${end}MiB
    start=$end

    # Partition 4: Shared data (rest of disk)
    parted -s "$OUTPUT_FILE" mkpart shared-data ext4 ${start}MiB 100%

    parted -s "$OUTPUT_FILE" print
}

setup_loop() {
    log "Setting up loop device..."
    LOOP_DEV=$(losetup -f --show -P "$OUTPUT_FILE")
    log "Loop device: $LOOP_DEV"
    sleep 1
}

format_partitions() {
    log "Formatting partitions..."

    mkfs.vfat -F 32 -n SECUBOX-EFI "${LOOP_DEV}p1"
    mkfs.ext4 -L secubox-arm64 "${LOOP_DEV}p2"
    mkfs.ext4 -L secubox-amd64 "${LOOP_DEV}p3"
    mkfs.ext4 -L secubox-data "${LOOP_DEV}p4"
}

mount_partitions() {
    log "Mounting partitions..."

    MNT_EFI=$(mktemp -d)
    MNT_ARM64=$(mktemp -d)
    MNT_AMD64=$(mktemp -d)
    MNT_DATA=$(mktemp -d)

    mount "${LOOP_DEV}p1" "$MNT_EFI"
    mount "${LOOP_DEV}p2" "$MNT_ARM64"
    mount "${LOOP_DEV}p3" "$MNT_AMD64"
    mount "${LOOP_DEV}p4" "$MNT_DATA"
}

install_efi_boot() {
    log "Installing EFI boot files..."

    mkdir -p "$MNT_EFI/EFI/BOOT"
    mkdir -p "$MNT_EFI/grub"
    mkdir -p "$MNT_EFI/dtbs/marvell"
    mkdir -p "$MNT_EFI/flash"

    # Install GRUB for AMD64 UEFI
    if command -v grub-mkimage &>/dev/null; then
        grub-mkimage -o "$MNT_EFI/EFI/BOOT/BOOTX64.EFI" \
            -O x86_64-efi \
            -p /grub \
            part_gpt part_msdos fat ext2 normal linux boot \
            configfile loopback chain efifwsetup efi_gop \
            efi_uga ls search search_label search_fs_uuid \
            search_fs_file gfxterm gfxterm_background gfxmenu test all_video
    fi

    # GRUB config for AMD64
    cat > "$MNT_EFI/grub/grub.cfg" <<'GRUBCFG'
set timeout=5
set default=0

menuentry "SecuBox AMD64 Live" {
    linux /vmlinuz root=LABEL=secubox-amd64 ro quiet
    initrd /initrd-amd64.img
}

menuentry "SecuBox AMD64 Live (Recovery)" {
    linux /vmlinuz root=LABEL=secubox-amd64 ro single
    initrd /initrd-amd64.img
}

menuentry "Flash SecuBox to eMMC (ARM64 only)" {
    echo "This option is for ARM64 systems only"
    echo "Boot the ARM64 system and run: secubox-flash-emmc"
    sleep 5
}
GRUBCFG

    # Copy GRUB config to EFI/BOOT as well
    cp "$MNT_EFI/grub/grub.cfg" "$MNT_EFI/EFI/BOOT/"
}

install_uboot_boot() {
    log "Installing U-Boot boot files for ARM64..."

    # Create boot.scr for ARM64 (ESPRESSObin)
    cat > /tmp/boot.cmd <<'BOOTCMD'
# SecuBox Multi-Boot U-Boot Script
# For ESPRESSObin/MOCHAbin ARM64

echo "============================================"
echo "SecuBox Multi-Boot — ARM64"
echo "============================================"

# Detect boot device
if test "${devtype}" = "usb"; then
    setenv bootpart "usb 0:1"
    setenv rootpart "/dev/sda2"
    echo "Booting from USB storage"
elif test "${devtype}" = "mmc"; then
    setenv bootpart "mmc ${devnum}:1"
    setenv rootpart "/dev/mmcblk${devnum}p2"
    echo "Booting from MMC/SD"
else
    # Default to USB
    usb start
    setenv bootpart "usb 0:1"
    setenv rootpart "/dev/sda2"
fi

# Load kernel
echo "Loading ARM64 kernel..."
load ${bootpart} ${kernel_addr_r} Image

# Load device tree
echo "Loading device tree..."
if load ${bootpart} ${fdt_addr_r} dtbs/marvell/armada-3720-espressobin-v7-emmc.dtb; then
    echo "Loaded ESPRESSObin v7 eMMC DTB"
else
    load ${bootpart} ${fdt_addr_r} dtbs/marvell/armada-3720-espressobin-v7.dtb
fi

# Load initramfs
echo "Loading initramfs..."
if load ${bootpart} ${ramdisk_addr_r} initrd.img; then
    setenv initrd_size ${filesize}
    setenv use_initrd 1
else
    setenv use_initrd 0
fi

# Boot arguments
# Data partition is partition 4
setenv bootargs "root=${rootpart} rootfstype=ext4 rootwait rootdelay=5 console=ttyMV0,115200 net.ifnames=0 secubox.data=/dev/sda4"

echo "Booting SecuBox ARM64..."
if test "${use_initrd}" = "1"; then
    booti ${kernel_addr_r} ${ramdisk_addr_r}:${initrd_size} ${fdt_addr_r}
else
    booti ${kernel_addr_r} - ${fdt_addr_r}
fi
BOOTCMD

    # Compile boot.scr if mkimage available
    if command -v mkimage &>/dev/null; then
        mkimage -A arm64 -T script -C none -d /tmp/boot.cmd "$MNT_EFI/boot.scr"
    else
        cp /tmp/boot.cmd "$MNT_EFI/boot.cmd"
    fi
}

install_arm64_rootfs() {
    log "Installing ARM64 rootfs..."

    if [[ -n "$ARM64_ROOTFS" && -d "$ARM64_ROOTFS" ]]; then
        log "Copying from $ARM64_ROOTFS"
        rsync -aHAX "$ARM64_ROOTFS/" "$MNT_ARM64/"
    else
        # Check for existing built image
        local arm64_img="${OUTPUT_DIR}/secubox-espressobin-v7-bookworm.img"
        if [[ -f "$arm64_img" ]]; then
            log "Extracting rootfs from $arm64_img"
            local tmp_loop=$(losetup -f --show -P "$arm64_img")
            local tmp_mnt=$(mktemp -d)
            mount "${tmp_loop}p2" "$tmp_mnt"
            rsync -aHAX "$tmp_mnt/" "$MNT_ARM64/"
            umount "$tmp_mnt"
            losetup -d "$tmp_loop"
            rmdir "$tmp_mnt"

            # Also copy kernel/initrd/dtbs to EFI partition
            mount "${tmp_loop}p1" "$tmp_mnt" 2>/dev/null || true
            if [[ -f "$tmp_mnt/Image" ]]; then
                cp "$tmp_mnt/Image" "$MNT_EFI/"
                cp "$tmp_mnt/initrd.img" "$MNT_EFI/" 2>/dev/null || true
                cp -r "$tmp_mnt/dtbs" "$MNT_EFI/" 2>/dev/null || true
            fi
            umount "$tmp_mnt" 2>/dev/null || true
        else
            log "WARNING: No ARM64 rootfs source found, partition will be empty"
        fi
    fi

    # Setup shared data mounts in fstab
    setup_shared_mounts "$MNT_ARM64"
}

install_amd64_rootfs() {
    log "Installing AMD64 rootfs..."

    if [[ -n "$AMD64_ROOTFS" && -d "$AMD64_ROOTFS" ]]; then
        log "Copying from $AMD64_ROOTFS"
        rsync -aHAX "$AMD64_ROOTFS/" "$MNT_AMD64/"
    else
        # Build AMD64 rootfs with debootstrap
        log "Building AMD64 rootfs with debootstrap..."
        "${SCRIPT_DIR}/build-amd64-rootfs.sh" --output "$MNT_AMD64" --minimal
    fi

    # Copy AMD64 kernel to EFI partition
    if [[ -f "$MNT_AMD64/boot/vmlinuz-"* ]]; then
        cp "$MNT_AMD64/boot/vmlinuz-"* "$MNT_EFI/vmlinuz"
        cp "$MNT_AMD64/boot/initrd.img-"* "$MNT_EFI/initrd-amd64.img" 2>/dev/null || true
    fi

    # Setup shared data mounts in fstab
    setup_shared_mounts "$MNT_AMD64"
}

setup_shared_mounts() {
    local rootfs="$1"

    log "Setting up shared data mounts for $rootfs"

    # Create mount points
    mkdir -p "$rootfs/srv/data"

    # Add to fstab
    cat >> "$rootfs/etc/fstab" <<'FSTAB'

# SecuBox Shared Data Partition
LABEL=secubox-data  /srv/data  ext4  defaults,noatime  0  2
FSTAB

    # Create systemd mount for bind mounts
    mkdir -p "$rootfs/etc/systemd/system"
    cat > "$rootfs/etc/systemd/system/secubox-shared-data.service" <<'SERVICE'
[Unit]
Description=SecuBox Shared Data Bind Mounts
After=srv-data.mount
Requires=srv-data.mount

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/secubox-mount-shared

[Install]
WantedBy=multi-user.target
SERVICE

    # Create mount script
    mkdir -p "$rootfs/usr/local/bin"
    cat > "$rootfs/usr/local/bin/secubox-mount-shared" <<'SCRIPT'
#!/bin/bash
# Mount shared SecuBox data directories

DATA_ROOT="/srv/data"

# Create shared directories if they don't exist
mkdir -p "$DATA_ROOT"/{etc/secubox,var/lib/secubox,srv/secubox,log/secubox}

# Bind mount shared configs
mkdir -p /etc/secubox
mount --bind "$DATA_ROOT/etc/secubox" /etc/secubox

# Bind mount application state
mkdir -p /var/lib/secubox
mount --bind "$DATA_ROOT/var/lib/secubox" /var/lib/secubox

# Bind mount service data
mkdir -p /srv/secubox
mount --bind "$DATA_ROOT/srv/secubox" /srv/secubox

# Bind mount logs
mkdir -p /var/log/secubox
mount --bind "$DATA_ROOT/log/secubox" /var/log/secubox

echo "SecuBox shared data mounted"
SCRIPT
    chmod +x "$rootfs/usr/local/bin/secubox-mount-shared"

    # Enable the service
    ln -sf ../secubox-shared-data.service "$rootfs/etc/systemd/system/multi-user.target.wants/" 2>/dev/null || true
}

setup_shared_data() {
    log "Setting up shared data partition structure..."

    mkdir -p "$MNT_DATA"/{etc/secubox,var/lib/secubox,srv/secubox,log/secubox}
    mkdir -p "$MNT_DATA/etc/secubox"/{tls,modules}
    mkdir -p "$MNT_DATA/var/lib/secubox"/{crowdsec,haproxy,wireguard,dpi,hub}
    mkdir -p "$MNT_DATA/srv/secubox"/{mitmproxy,nginx,certs}

    # Create default configs
    cat > "$MNT_DATA/etc/secubox/api.toml" <<'TOML'
# SecuBox API Configuration (Shared)
[api]
jwt_secret = ""  # Generated on first boot

[logging]
level = "INFO"
TOML

    # Create empty users.json
    echo '{}' > "$MNT_DATA/etc/secubox/users.json"

    # Set permissions
    chmod 750 "$MNT_DATA/etc/secubox"
    chmod 750 "$MNT_DATA/var/lib/secubox"
}

install_emmc_flasher() {
    if [[ "$INCLUDE_EMMC" != "true" ]]; then
        log "Skipping eMMC flasher image"
        return
    fi

    log "Installing eMMC flasher image..."

    mkdir -p "$MNT_EFI/flash"

    if [[ -n "$EMMC_IMAGE" && -f "$EMMC_IMAGE" ]]; then
        if [[ "$EMMC_IMAGE" == *.gz ]]; then
            cp "$EMMC_IMAGE" "$MNT_EFI/flash/secubox-emmc.img.gz"
        else
            gzip -c "$EMMC_IMAGE" > "$MNT_EFI/flash/secubox-emmc.img.gz"
        fi
    else
        # Look for existing image
        local emmc_img="${OUTPUT_DIR}/secubox-espressobin-v7-bookworm.img"
        if [[ -f "$emmc_img" ]]; then
            log "Compressing $emmc_img for eMMC flash..."
            gzip -c "$emmc_img" > "$MNT_EFI/flash/secubox-emmc.img.gz"
        else
            log "WARNING: No eMMC image found, flash directory will be empty"
        fi
    fi

    # Create flash script
    cat > "$MNT_EFI/flash/flash-emmc.sh" <<'FLASH'
#!/bin/bash
# SecuBox eMMC Flasher
set -e

EMMC_DEV="/dev/mmcblk0"
IMG="/boot/efi/flash/secubox-emmc.img.gz"

echo "============================================"
echo "SecuBox eMMC Flasher"
echo "============================================"

if [[ ! -f "$IMG" ]]; then
    echo "ERROR: Image not found: $IMG"
    exit 1
fi

if [[ ! -b "$EMMC_DEV" ]]; then
    echo "ERROR: eMMC device not found: $EMMC_DEV"
    echo "Available block devices:"
    lsblk
    exit 1
fi

echo "WARNING: This will erase all data on $EMMC_DEV"
echo "Image: $IMG"
echo ""
read -p "Continue? [y/N] " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "Aborted."
    exit 0
fi

echo "Flashing to $EMMC_DEV..."
gunzip -c "$IMG" | dd of="$EMMC_DEV" bs=4M status=progress conv=fsync

echo "Syncing..."
sync

echo "============================================"
echo "Flash complete! You can now boot from eMMC."
echo "============================================"
FLASH
    chmod +x "$MNT_EFI/flash/flash-emmc.sh"
}

cleanup() {
    log "Cleaning up..."

    umount "$MNT_EFI" 2>/dev/null || true
    umount "$MNT_ARM64" 2>/dev/null || true
    umount "$MNT_AMD64" 2>/dev/null || true
    umount "$MNT_DATA" 2>/dev/null || true

    [[ -n "${LOOP_DEV:-}" ]] && losetup -d "$LOOP_DEV" 2>/dev/null || true

    rmdir "$MNT_EFI" "$MNT_ARM64" "$MNT_AMD64" "$MNT_DATA" 2>/dev/null || true
}

main() {
    parse_args "$@"
    check_deps

    trap cleanup EXIT

    log "Building SecuBox Multi-Boot Image"
    log "Size: $IMAGE_SIZE"
    log "Output: $OUTPUT_FILE"

    create_image
    partition_image
    setup_loop
    format_partitions
    mount_partitions

    install_efi_boot
    install_uboot_boot
    install_arm64_rootfs
    install_amd64_rootfs
    setup_shared_data
    install_emmc_flasher

    log "============================================"
    log "Multi-Boot Image Complete: $OUTPUT_FILE"
    log "============================================"
    log "Partitions:"
    log "  1: EFI/Boot (FAT32) - UEFI + U-Boot"
    log "  2: ARM64 rootfs (ext4)"
    log "  3: AMD64 rootfs (ext4)"
    log "  4: Shared data (ext4)"
}

main "$@"
