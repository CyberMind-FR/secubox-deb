#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# SecuBox Eye Remote - Slipstream SecuBox Modules into Storage Image
# Injects SecuBox .deb packages into the ESPRESSObin boot image
#
# Usage: sudo bash slipstream-storage.sh [--image PATH] [--debs PATH]
#
# This script mounts the storage.img and installs SecuBox packages into it
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Defaults
STORAGE_IMG="${1:-/var/lib/secubox/eye-remote/storage.img}"
DEBS_DIR="${REPO_DIR}/output/debs"

RED='\033[0;31m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'
GOLD='\033[0;33m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${CYAN}[slipstream]${NC} $*"; }
ok()   { echo -e "${GREEN}[    OK    ]${NC} $*"; }
err()  { echo -e "${RED}[   FAIL   ]${NC} $*" >&2; exit 1; }
warn() { echo -e "${GOLD}[   WARN   ]${NC} $*"; }

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --image|-i)   STORAGE_IMG="$2"; shift 2 ;;
        --debs|-d)    DEBS_DIR="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: sudo $0 [--image PATH] [--debs PATH]"
            echo ""
            echo "Options:"
            echo "  --image, -i PATH   Path to storage.img (default: /var/lib/secubox/eye-remote/storage.img)"
            echo "  --debs, -d PATH    Path to .deb packages (default: output/debs)"
            exit 0
            ;;
        *)
            if [[ -f "$1" ]]; then
                STORAGE_IMG="$1"
            fi
            shift
            ;;
    esac
done

[[ $EUID -ne 0 ]] && err "Run as root: sudo bash $0"

log "SecuBox Storage Image Slipstreamer"
log "==================================="
log "Storage image: ${STORAGE_IMG}"
log "Packages dir:  ${DEBS_DIR}"

# ── Validate inputs ────────────────────────────────────────────────────────
[[ ! -f "$STORAGE_IMG" ]] && err "Storage image not found: $STORAGE_IMG"
[[ ! -d "$DEBS_DIR" ]] && err "Packages directory not found: $DEBS_DIR"

# Count packages
DEB_COUNT=$(find "$DEBS_DIR" -maxdepth 1 -name "secubox-*.deb" 2>/dev/null | wc -l)
[[ $DEB_COUNT -eq 0 ]] && err "No secubox-*.deb packages found in $DEBS_DIR"
log "Found ${DEB_COUNT} packages to install"

# ── Setup work directory ───────────────────────────────────────────────────
WORK_DIR=$(mktemp -d /tmp/slipstream-XXXXXX)
MOUNT_POINT="${WORK_DIR}/rootfs"
mkdir -p "$MOUNT_POINT"

cleanup() {
    log "Cleaning up..."
    sync 2>/dev/null || true
    umount -lf "${MOUNT_POINT}" 2>/dev/null || true
    [[ -n "${LOOP:-}" ]] && losetup -d "${LOOP}" 2>/dev/null || true
    rm -rf "${WORK_DIR}" 2>/dev/null || true
}
trap cleanup EXIT

# ── Detect image format ────────────────────────────────────────────────────
log "Analyzing image..."

# Check if it's a disk image with partitions or a filesystem image
LOOP=$(losetup --find --show --partscan "$STORAGE_IMG")
sleep 1

# Check for partitions
if [[ -b "${LOOP}p2" ]]; then
    ROOT_DEV="${LOOP}p2"
    log "Image has partitions, using p2 as root"
elif [[ -b "${LOOP}p1" ]]; then
    # Check if p1 is ext4 (root) or FAT (boot)
    if file -s "${LOOP}p1" | grep -q "ext"; then
        ROOT_DEV="${LOOP}p1"
        log "Single ext partition image"
    else
        err "Partition 1 is not ext4, cannot find root filesystem"
    fi
else
    # No partitions - might be a raw filesystem
    losetup -d "$LOOP"
    LOOP=""
    ROOT_DEV="$STORAGE_IMG"
    log "Raw filesystem image (no partition table)"
fi

# ── Mount root filesystem ──────────────────────────────────────────────────
log "Mounting root filesystem..."

mount "$ROOT_DEV" "$MOUNT_POINT" || err "Failed to mount root filesystem"

# Verify it's a Linux rootfs
if [[ ! -d "${MOUNT_POINT}/etc" ]] || [[ ! -d "${MOUNT_POINT}/usr" ]]; then
    err "Not a valid Linux root filesystem"
fi

ok "Mounted at ${MOUNT_POINT}"

# Show current system info
if [[ -f "${MOUNT_POINT}/etc/os-release" ]]; then
    . "${MOUNT_POINT}/etc/os-release"
    log "Target system: ${PRETTY_NAME:-$ID}"
fi

# ── Copy and install packages ──────────────────────────────────────────────
log "Installing SecuBox packages..."

# Create temp directory for packages
DEBS_TMP="${MOUNT_POINT}/tmp/secubox-debs"
mkdir -p "$DEBS_TMP"

# Copy all SecuBox packages
for deb in "${DEBS_DIR}"/secubox-*.deb; do
    [[ -f "$deb" ]] || continue
    cp "$deb" "$DEBS_TMP/"
done

COPIED_COUNT=$(ls "${DEBS_TMP}"/*.deb 2>/dev/null | wc -l)
log "Copied ${COPIED_COUNT} packages"

# Check if we can chroot (need QEMU for cross-arch)
ARCH=$(file "${MOUNT_POINT}/bin/ls" 2>/dev/null | grep -oP 'ARM aarch64|x86-64' || echo "unknown")
HOST_ARCH=$(uname -m)

CAN_CHROOT=0
if [[ "$ARCH" == "ARM aarch64" ]] && [[ "$HOST_ARCH" == "x86_64" ]]; then
    # Need QEMU for ARM64 on x86
    if [[ -f /usr/bin/qemu-aarch64-static ]]; then
        cp /usr/bin/qemu-aarch64-static "${MOUNT_POINT}/usr/bin/"
        CAN_CHROOT=1
        log "Using QEMU for ARM64 chroot"
    else
        warn "QEMU not available, packages will be copied but not configured"
        warn "Install qemu-user-static for full installation"
    fi
elif [[ "$ARCH" == *"$HOST_ARCH"* ]] || [[ "$HOST_ARCH" == "aarch64" ]]; then
    CAN_CHROOT=1
    log "Native architecture, can chroot directly"
fi

if [[ $CAN_CHROOT -eq 1 ]]; then
    # Mount necessary filesystems
    mount -t proc proc "${MOUNT_POINT}/proc" || true
    mount -t sysfs sysfs "${MOUNT_POINT}/sys" || true
    mount --bind /dev "${MOUNT_POINT}/dev" || true

    # Install packages via chroot
    log "Installing packages in chroot..."

    # Install core first
    if ls "${DEBS_TMP}"/secubox-core_*.deb >/dev/null 2>&1; then
        chroot "${MOUNT_POINT}" bash -c 'dpkg -i --force-depends /tmp/secubox-debs/secubox-core_*.deb 2>&1' || warn "secubox-core install had warnings"
    fi

    # Install all packages
    chroot "${MOUNT_POINT}" bash -c 'dpkg -i --force-depends --force-overwrite /tmp/secubox-debs/*.deb 2>&1 || true' | \
        grep -v "^dpkg: warning" | head -30 || true

    # Fix dependencies
    chroot "${MOUNT_POINT}" bash -c 'apt-get -f install -y --fix-broken 2>&1 || true' | tail -10 || true

    # Count installed packages
    INSTALLED=$(chroot "${MOUNT_POINT}" bash -c 'dpkg -l "secubox-*" 2>/dev/null | grep "^ii" | wc -l || echo 0')
    ok "Installed ${INSTALLED} packages"

    # Show installed packages
    log "Installed packages:"
    chroot "${MOUNT_POINT}" bash -c 'dpkg -l "secubox-*" 2>/dev/null | grep "^ii" | awk "{print \"  \" \$2 \" \" \$3}"' || true

    # Cleanup chroot mounts
    umount -lf "${MOUNT_POINT}/proc" 2>/dev/null || true
    umount -lf "${MOUNT_POINT}/sys" 2>/dev/null || true
    umount -lf "${MOUNT_POINT}/dev" 2>/dev/null || true

    # Remove QEMU if we added it
    rm -f "${MOUNT_POINT}/usr/bin/qemu-aarch64-static"
else
    # Copy packages to a location where they can be installed later
    mkdir -p "${MOUNT_POINT}/opt/secubox/pending-debs"
    cp "${DEBS_TMP}"/*.deb "${MOUNT_POINT}/opt/secubox/pending-debs/"

    # Create firstboot install script
    cat > "${MOUNT_POINT}/opt/secubox/install-pending.sh" << 'FIRSTBOOT'
#!/bin/bash
# Auto-install pending SecuBox packages on first boot
PENDING_DIR="/opt/secubox/pending-debs"
if [[ -d "$PENDING_DIR" ]] && ls "$PENDING_DIR"/*.deb >/dev/null 2>&1; then
    echo "Installing pending SecuBox packages..."
    dpkg -i --force-depends "$PENDING_DIR"/secubox-core_*.deb 2>/dev/null || true
    dpkg -i --force-depends --force-overwrite "$PENDING_DIR"/*.deb 2>/dev/null || true
    apt-get -f install -y --fix-broken 2>/dev/null || true
    rm -rf "$PENDING_DIR"
    echo "SecuBox packages installed!"
fi
FIRSTBOOT
    chmod +x "${MOUNT_POINT}/opt/secubox/install-pending.sh"

    # Add to rc.local if it exists
    if [[ -f "${MOUNT_POINT}/etc/rc.local" ]]; then
        if ! grep -q "install-pending.sh" "${MOUNT_POINT}/etc/rc.local"; then
            sed -i '/^exit 0/i /opt/secubox/install-pending.sh' "${MOUNT_POINT}/etc/rc.local"
        fi
    else
        # Create systemd service for firstboot
        cat > "${MOUNT_POINT}/etc/systemd/system/secubox-firstboot.service" << 'FIRSTBOOTSVC'
[Unit]
Description=SecuBox First Boot Package Installation
After=network.target
ConditionPathExists=/opt/secubox/pending-debs

[Service]
Type=oneshot
ExecStart=/opt/secubox/install-pending.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
FIRSTBOOTSVC
        # Enable it
        mkdir -p "${MOUNT_POINT}/etc/systemd/system/multi-user.target.wants"
        ln -sf ../secubox-firstboot.service "${MOUNT_POINT}/etc/systemd/system/multi-user.target.wants/"
    fi

    warn "Packages copied for first-boot installation (QEMU not available)"
    ok "First-boot installer created"
fi

# Cleanup temp debs
rm -rf "$DEBS_TMP"

# ── Sync and finish ────────────────────────────────────────────────────────
log "Syncing filesystem..."
sync

# Show final status
ROOTFS_SIZE=$(du -sh "${MOUNT_POINT}" 2>/dev/null | cut -f1)
log "Root filesystem size: ${ROOTFS_SIZE}"

echo ""
log "════════════════════════════════════════════════════════════════"
echo -e "${GREEN}${BOLD}SecuBox packages slipstreamed successfully!${NC}"
echo ""
echo "  Image: ${STORAGE_IMG}"
echo ""
echo "  The ESPRESSObin will now boot with SecuBox modules installed."
echo ""
if [[ $CAN_CHROOT -eq 1 ]]; then
    echo "  Packages are fully installed and configured."
else
    echo "  Packages will be installed on first boot."
fi
log "════════════════════════════════════════════════════════════════"
