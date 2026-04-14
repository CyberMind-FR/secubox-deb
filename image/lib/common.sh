#!/bin/bash
# ══════════════════════════════════════════════════════════════════
# SecuBox-DEB Build Library - Common Functions
# Shared utilities for all build scripts
# ══════════════════════════════════════════════════════════════════

# ── Colors and Logging ─────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# Logging prefix (set by each profile)
LOG_PREFIX="${LOG_PREFIX:-build}"

log()  { echo -e "${CYAN}[$LOG_PREFIX]${RESET} $*"; }
ok()   { echo -e "${GREEN}[  OK   ]${RESET} $*"; }
warn() { echo -e "${YELLOW}[ WARN  ]${RESET} $*"; }
err()  { echo -e "${RED}[ERROR!]${RESET} $*" >&2; }
die()  { err "$*"; cleanup; exit 1; }

# ── Build Configuration ────────────────────────────────────────────
# These can be overridden by profiles
BUILD_VERSION="${BUILD_VERSION:-1.7.0}"
BUILD_DATE=$(date +%Y%m%d)
DEBIAN_RELEASE="${DEBIAN_RELEASE:-bookworm}"
DEBIAN_MIRROR="${DEBIAN_MIRROR:-http://deb.debian.org/debian}"
DEBIAN_SECURITY="${DEBIAN_SECURITY:-http://security.debian.org/debian-security}"

# Output paths
OUTPUT_DIR="${OUTPUT_DIR:-output}"
PACKAGES_DIR="${PACKAGES_DIR:-output/packages}"

# Feature flags
INCLUDE_KIOSK="${INCLUDE_KIOSK:-0}"
INCLUDE_SLIPSTREAM="${INCLUDE_SLIPSTREAM:-0}"
VERBOSE="${VERBOSE:-0}"

# ── Cleanup Stack ──────────────────────────────────────────────────
CLEANUP_STACK=()
LOOP_DEV=""
MOUNT_POINT=""

push_cleanup() {
    CLEANUP_STACK+=("$1")
}

cleanup() {
    log "Cleaning up..."

    # Execute cleanup stack in reverse order
    for (( i=${#CLEANUP_STACK[@]}-1; i>=0; i-- )); do
        eval "${CLEANUP_STACK[i]}" 2>/dev/null || true
    done

    # Standard cleanup
    [[ -n "$MOUNT_POINT" && -d "$MOUNT_POINT" ]] && {
        umount -R "$MOUNT_POINT" 2>/dev/null || true
        rmdir "$MOUNT_POINT" 2>/dev/null || true
    }

    [[ -n "$LOOP_DEV" && -b "$LOOP_DEV" ]] && {
        losetup -d "$LOOP_DEV" 2>/dev/null || true
    }
}

trap cleanup EXIT INT TERM

# ── Utility Functions ──────────────────────────────────────────────

# Check if running as root
require_root() {
    [[ $EUID -eq 0 ]] || die "This script must be run as root"
}

# Check required commands
check_commands() {
    local cmds=("$@")
    for cmd in "${cmds[@]}"; do
        command -v "$cmd" &>/dev/null || die "Missing required command: $cmd"
    done
}

# Find free loop device
find_loop_device() {
    losetup -f 2>/dev/null || die "No free loop devices available"
}

# Setup loop device with partitions
setup_loop() {
    local img="$1"
    LOOP_DEV=$(losetup -fP --show "$img") || die "Failed to setup loop device for $img"
    push_cleanup "losetup -d $LOOP_DEV"
    echo "$LOOP_DEV"
}

# Mount partition
mount_partition() {
    local device="$1"
    local mount_point="$2"
    local options="${3:-}"

    mkdir -p "$mount_point"
    if [[ -n "$options" ]]; then
        mount -o "$options" "$device" "$mount_point" || die "Failed to mount $device"
    else
        mount "$device" "$mount_point" || die "Failed to mount $device"
    fi
    push_cleanup "umount $mount_point"
}

# Create temporary mount point
create_temp_mount() {
    MOUNT_POINT=$(mktemp -d) || die "Failed to create temp directory"
    push_cleanup "rmdir $MOUNT_POINT"
    echo "$MOUNT_POINT"
}

# Run command in chroot
run_chroot() {
    local root="$1"
    shift
    chroot "$root" /bin/bash -c "$*"
}

# Run command in chroot with proper mounts
run_chroot_mounted() {
    local root="$1"
    shift

    # Bind mount essential filesystems
    for fs in proc sys dev dev/pts; do
        mount --bind "/$fs" "$root/$fs" 2>/dev/null || true
    done

    # Copy resolv.conf for network access
    cp /etc/resolv.conf "$root/etc/resolv.conf" 2>/dev/null || true

    # Run command
    chroot "$root" /bin/bash -c "$*"
    local ret=$?

    # Unmount
    for fs in dev/pts dev sys proc; do
        umount "$root/$fs" 2>/dev/null || true
    done

    return $ret
}

# Copy packages to chroot for slipstream
copy_packages_for_slipstream() {
    local root="$1"
    local pkgdir="${2:-$PACKAGES_DIR}"
    local destdir="$root/tmp/secubox-debs"

    mkdir -p "$destdir"

    if [[ -d "$pkgdir" ]]; then
        local count=$(ls "$pkgdir"/*.deb 2>/dev/null | wc -l)
        if [[ $count -gt 0 ]]; then
            cp "$pkgdir"/*.deb "$destdir/"
            log "Copied $count packages for slipstream"
            return 0
        fi
    fi

    warn "No packages found in $pkgdir"
    return 1
}

# Install slipstream packages in chroot
install_slipstream_packages() {
    local root="$1"
    local destdir="$root/tmp/secubox-debs"

    [[ -d "$destdir" ]] || return 1

    run_chroot_mounted "$root" "
        cd /tmp/secubox-debs
        # Install with --force-depends to handle pip-installed Python packages
        dpkg -i --force-depends *.deb 2>/dev/null || true
        # Fix any broken dependencies
        apt-get -f install -y --no-install-recommends 2>/dev/null || true
        rm -rf /tmp/secubox-debs
    "
}

# Install Python packages via pip
install_pip_packages() {
    local root="$1"
    shift
    local packages=("$@")

    run_chroot_mounted "$root" "
        pip3 install --break-system-packages ${packages[*]} 2>/dev/null || \
        pip3 install ${packages[*]}
    "
}

# ── Image Creation ─────────────────────────────────────────────────

# Create raw disk image
create_disk_image() {
    local img="$1"
    local size="$2"  # e.g., 4G, 8G

    log "Creating ${size} disk image: $img"
    dd if=/dev/zero of="$img" bs=1M count=0 seek="${size%G}000" 2>/dev/null || \
    fallocate -l "$size" "$img" || \
    truncate -s "$size" "$img" || \
    die "Failed to create disk image"
}

# Partition disk image (GPT with ESP + rootfs)
partition_gpt_efi() {
    local img="$1"
    local esp_size="${2:-512M}"

    log "Partitioning disk image (GPT + EFI)"
    parted -s "$img" \
        mklabel gpt \
        mkpart ESP fat32 1MiB "$esp_size" \
        set 1 esp on \
        mkpart rootfs ext4 "$esp_size" 100% \
        || die "Failed to partition disk"
}

# Partition disk image for RPi (MBR with fat32 boot + ext4 root)
partition_rpi() {
    local img="$1"
    local boot_size="${2:-512M}"

    log "Partitioning disk image (MBR for RPi)"
    parted -s "$img" \
        mklabel msdos \
        mkpart primary fat32 4MiB "$boot_size" \
        set 1 boot on \
        mkpart primary ext4 "$boot_size" 100% \
        || die "Failed to partition disk"
}

# Format partitions
format_partitions() {
    local loop="$1"
    local type="$2"  # efi or rpi

    case "$type" in
        efi)
            mkfs.vfat -F32 -n ESP "${loop}p1" || die "Failed to format ESP"
            mkfs.ext4 -L rootfs "${loop}p2" || die "Failed to format rootfs"
            ;;
        rpi)
            mkfs.vfat -F32 -n boot "${loop}p1" || die "Failed to format boot"
            mkfs.ext4 -L rootfs "${loop}p2" || die "Failed to format rootfs"
            ;;
        *)
            die "Unknown partition type: $type"
            ;;
    esac
}

# ── Debootstrap ────────────────────────────────────────────────────

# Run debootstrap for architecture
run_debootstrap() {
    local root="$1"
    local arch="$2"
    local suite="${3:-$DEBIAN_RELEASE}"
    local mirror="${4:-$DEBIAN_MIRROR}"
    local include="${5:-}"

    local debootstrap_opts=(
        --arch="$arch"
        --variant=minbase
    )

    [[ -n "$include" ]] && debootstrap_opts+=(--include="$include")

    # For ARM64 cross-debootstrap
    if [[ "$arch" == "arm64" && "$(dpkg --print-architecture)" != "arm64" ]]; then
        debootstrap_opts+=(--foreign)
    fi

    log "Running debootstrap for $arch..."
    debootstrap "${debootstrap_opts[@]}" "$suite" "$root" "$mirror" || \
        die "Debootstrap failed"

    # Second stage for foreign arch
    if [[ "$arch" == "arm64" && "$(dpkg --print-architecture)" != "arm64" ]]; then
        log "Running debootstrap second stage..."
        run_chroot "$root" "/debootstrap/debootstrap --second-stage"
    fi
}

# Configure APT sources
configure_apt_sources() {
    local root="$1"
    local suite="${2:-$DEBIAN_RELEASE}"

    cat > "$root/etc/apt/sources.list" << EOF
deb $DEBIAN_MIRROR $suite main contrib non-free non-free-firmware
deb $DEBIAN_MIRROR $suite-updates main contrib non-free non-free-firmware
deb $DEBIAN_SECURITY ${suite}-security main contrib non-free non-free-firmware
EOF
}

# ── Compression and Finalization ───────────────────────────────────

# Compress image with gzip
compress_image() {
    local img="$1"
    local out="${2:-${img}.gz}"

    log "Compressing image..."
    gzip -9 -c "$img" > "$out" || die "Failed to compress image"
    ok "Created compressed image: $(du -h "$out" | cut -f1)"
}

# Generate SHA256 checksum
generate_checksum() {
    local file="$1"
    local sum_file="${file}.sha256"

    sha256sum "$file" | sed "s|.*/||" > "$sum_file"
    ok "Generated checksum: $sum_file"
}

# ── Splash Screen Installation ─────────────────────────────────────

install_splash_screens() {
    local root="$1"
    local splash_dir="${2:-image/splash}"

    [[ -d "$splash_dir" ]] || return 0

    mkdir -p "$root/usr/share/secubox/splash"
    cp "$splash_dir"/* "$root/usr/share/secubox/splash/" 2>/dev/null || true

    # Make scripts executable
    chmod +x "$root/usr/share/secubox/splash"/*.sh 2>/dev/null || true

    ok "Installed splash screens"
}
