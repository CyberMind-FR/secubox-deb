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

    if [[ -z "$OUTPUT_FILE" ]]; then
        OUTPUT_FILE="${OUTPUT_DIR}/secubox-multiboot-$(date +%Y%m%d).img"
    fi
}

check_deps() {
    local deps=(parted mkfs.vfat mkfs.ext4 debootstrap losetup rsync)
    for cmd in "${deps[@]}"; do
        command -v "$cmd" &>/dev/null || err "Missing: $cmd"
    done
    # Optional deps - warn but don't fail
    command -v grub-mkimage &>/dev/null || log "WARNING: grub-mkimage not found, AMD64 UEFI boot may not work"
    command -v qemu-debootstrap &>/dev/null || log "WARNING: qemu-debootstrap not found, cross-arch debootstrap may fail"
    command -v mkimage &>/dev/null || log "WARNING: u-boot-tools mkimage not found, will use text boot.cmd"
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

    # Create boot.scr for ARM64 (ESPRESSObin) with dual boot menu
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
    # Set flag for flash mode
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
# boot=live: enable live-boot initramfs (RAM-based root)
# live-media-path: where to find filesystem.squashfs
# DSA switch blacklist - REQUIRED for ESPRESSObin live boot
# modprobe.blacklist: for loadable modules
# initcall_blacklist: for built-in drivers (live kernel has mv88e6xxx built-in)
setenv bootargs "boot=live live-media-path=/live root=${rootpart} rootfstype=ext4 rootwait rootdelay=10 console=ttyMV0,115200 net.ifnames=0 modprobe.blacklist=mv88e6xxx,mv88e6085,dsa_core initcall_blacklist=mv88e6xxx_driver_init secubox.data=${datapart} ${bootargs_extra}"

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

    # Compile boot.scr if mkimage available
    if command -v mkimage &>/dev/null; then
        mkimage -A arm64 -T script -C none -d /tmp/boot.cmd "$MNT_EFI/boot.scr"
    else
        cp /tmp/boot.cmd "$MNT_EFI/boot.cmd"
    fi
}

install_arm64_rootfs() {
    log "Installing ARM64 rootfs..."

    local kernel_installed=false

    if [[ -n "$ARM64_ROOTFS" && -d "$ARM64_ROOTFS" ]]; then
        log "Copying from $ARM64_ROOTFS"
        rsync -aHAX "$ARM64_ROOTFS/" "$MNT_ARM64/"
        # Check if kernel is available in the rootfs
        if [[ -f "$MNT_ARM64/boot/vmlinuz-"* ]]; then
            kernel_installed=true
        fi
    else
        # Check for existing built image
        local arm64_img="${OUTPUT_DIR}/secubox-espressobin-v7-bookworm.img"
        if [[ -f "$arm64_img" ]]; then
            log "Extracting rootfs from $arm64_img"
            local tmp_loop=$(losetup -f --show -P "$arm64_img")
            local tmp_mnt=$(mktemp -d)
            local tmp_boot=$(mktemp -d)

            # Mount rootfs partition and copy
            mount "${tmp_loop}p2" "$tmp_mnt"
            rsync -aHAX "$tmp_mnt/" "$MNT_ARM64/"

            # Check for kernel in rootfs
            if [[ -f "$MNT_ARM64/boot/vmlinuz-"* ]]; then
                kernel_installed=true
            fi

            umount "$tmp_mnt"

            # Mount boot partition and copy kernel files to EFI
            if mount "${tmp_loop}p1" "$tmp_boot" 2>/dev/null; then
                if [[ -f "$tmp_boot/Image" ]]; then
                    log "Copying ARM64 kernel from image boot partition..."
                    cp "$tmp_boot/Image" "$MNT_EFI/"
                    cp "$tmp_boot/initrd.img" "$MNT_EFI/" 2>/dev/null || true
                    cp -r "$tmp_boot/dtbs" "$MNT_EFI/" 2>/dev/null || true
                    kernel_installed=true
                fi
                umount "$tmp_boot"
            fi

            losetup -d "$tmp_loop"
            rmdir "$tmp_mnt" "$tmp_boot" 2>/dev/null || true
        else
            log "No pre-built ARM64 image found, building minimal rootfs with debootstrap..."
            build_arm64_rootfs_debootstrap
            kernel_installed=true
        fi
    fi

    # Copy kernel files from rootfs to EFI if not already done
    copy_arm64_kernel_to_efi

    # Setup shared data mounts in fstab
    setup_shared_mounts "$MNT_ARM64"
}

build_arm64_rootfs_debootstrap() {
    log "Building ARM64 rootfs with debootstrap..."

    # Bootstrap minimal Debian
    qemu-debootstrap --arch=arm64 \
        --include=systemd,systemd-sysv,dbus,udev,iproute2,iputils-ping,openssh-server,sudo,vim-tiny,linux-image-arm64 \
        bookworm "$MNT_ARM64" http://deb.debian.org/debian

    # Configure the rootfs
    cat > "$MNT_ARM64/etc/hostname" <<< "secubox"

    cat > "$MNT_ARM64/etc/hosts" <<'HOSTS'
127.0.0.1   localhost
127.0.1.1   secubox

::1         localhost ip6-localhost ip6-loopback
ff02::1     ip6-allnodes
ff02::2     ip6-allrouters
HOSTS

    # Set root password to 'secubox' (will be changed on first boot)
    chroot "$MNT_ARM64" /bin/bash -c "echo 'root:secubox' | chpasswd"

    # Enable serial console
    chroot "$MNT_ARM64" systemctl enable serial-getty@ttyMV0.service 2>/dev/null || true

    # Enable SSH
    chroot "$MNT_ARM64" systemctl enable ssh.service 2>/dev/null || true

    # Configure network
    cat > "$MNT_ARM64/etc/network/interfaces" <<'NETWORK'
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
NETWORK

    log "ARM64 rootfs built with kernel"
}

copy_arm64_kernel_to_efi() {
    log "Copying ARM64 kernel files to EFI partition..."

    # Find and copy kernel
    local vmlinuz=$(find "$MNT_ARM64/boot" -name 'vmlinuz-*' -type f 2>/dev/null | head -1)
    local initrd=$(find "$MNT_ARM64/boot" -name 'initrd.img-*' -type f 2>/dev/null | head -1)

    if [[ -n "$vmlinuz" && -f "$vmlinuz" ]]; then
        log "Found kernel: $vmlinuz"
        # ARM64 kernels need to be named 'Image' for U-Boot
        cp "$vmlinuz" "$MNT_EFI/Image"
    else
        log "WARNING: No ARM64 kernel found in rootfs"
    fi

    if [[ -n "$initrd" && -f "$initrd" ]]; then
        log "Found initrd: $initrd"
        cp "$initrd" "$MNT_EFI/initrd.img"
    fi

    # Copy device tree blobs
    mkdir -p "$MNT_EFI/dtbs/marvell"

    # Look for DTBs in various locations
    local dtb_sources=(
        "$MNT_ARM64/usr/lib/linux-image-"*"/marvell"
        "$MNT_ARM64/boot/dtbs/"*"/marvell"
        "$MNT_ARM64/boot/dtbs/marvell"
    )

    for dtb_dir in "${dtb_sources[@]}"; do
        if [[ -d "$dtb_dir" ]]; then
            log "Copying DTBs from: $dtb_dir"
            cp "$dtb_dir"/armada-3720-espressobin*.dtb "$MNT_EFI/dtbs/marvell/" 2>/dev/null || true
            cp "$dtb_dir"/armada-8040-mcbin*.dtb "$MNT_EFI/dtbs/marvell/" 2>/dev/null || true
            break
        fi
    done

    # Verify files were copied
    if [[ -f "$MNT_EFI/Image" ]]; then
        log "EFI partition kernel: $(ls -lh "$MNT_EFI/Image")"
    else
        log "ERROR: Failed to copy ARM64 kernel to EFI partition!"
    fi

    if [[ -d "$MNT_EFI/dtbs/marvell" ]]; then
        log "EFI partition DTBs: $(ls "$MNT_EFI/dtbs/marvell/" 2>/dev/null | wc -l) files"
    fi
}

install_amd64_rootfs() {
    log "Installing AMD64 rootfs..."

    if [[ -n "$AMD64_ROOTFS" && -d "$AMD64_ROOTFS" ]]; then
        log "Copying from $AMD64_ROOTFS"
        rsync -aHAX "$AMD64_ROOTFS/" "$MNT_AMD64/"
    else
        # Build AMD64 rootfs with debootstrap
        log "Building AMD64 rootfs with debootstrap..."
        "${SCRIPT_DIR}/build-amd64-rootfs.sh" --output "$MNT_AMD64"
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
