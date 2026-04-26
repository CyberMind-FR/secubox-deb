#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# SecuBox Eye Remote — Full Build Pipeline
# CyberMind — Gérald Kerma
#
# Complete build workflow:
#   Stage 1: Build SecuBox .deb packages (if missing/updated)
#   Stage 2: Build ESPRESSObin firmware with slipstreamed modules
#   Stage 3: Build Pi Zero SD image with embedded ESPRESSObin storage
#
# Usage: sudo bash build-eye-remote-full.sh [OPTIONS]
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

VERSION="2.2.1"
BUILD_DATE=$(date +%Y%m%d)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'
GOLD='\033[0;33m'; PURPLE='\033[0;35m'; NC='\033[0m'; BOLD='\033[1m'

log()    { echo -e "${CYAN}[build]${NC} $*"; }
stage()  { echo -e "\n${PURPLE}${BOLD}═══ $* ═══${NC}\n"; }
ok()     { echo -e "${GREEN}[  OK  ]${NC} $*"; }
err()    { echo -e "${RED}[ FAIL ]${NC} $*" >&2; exit 1; }
warn()   { echo -e "${GOLD}[ WARN ]${NC} $*"; }
skip()   { echo -e "${GOLD}[ SKIP ]${NC} $*"; }

# ── Defaults ──────────────────────────────────────────────────────────────────
OUTPUT_DIR="${SCRIPT_DIR}/output"
DEBS_DIR="${OUTPUT_DIR}/debs"
CACHE_DIR="${HOME}/.cache/secubox"

# Source images
EBIN_SOURCE="${SCRIPT_DIR}/board/secubox-espressobin-v7-bookworm.img.gz"
RPIZ_SOURCE=""  # Will auto-detect or download

# Output images - versioned filenames
EBIN_STORAGE_IMG="${OUTPUT_DIR}/eye-remote-storage-${VERSION}-${BUILD_DATE}.img"
RPIZ_SD_IMG="${OUTPUT_DIR}/secubox-eye-remote-${VERSION}-${BUILD_DATE}.img"

# Symlinks for latest (convenience)
EBIN_STORAGE_LATEST="${OUTPUT_DIR}/eye-remote-storage.img"
RPIZ_SD_LATEST="${OUTPUT_DIR}/secubox-eye-remote.img"

# Build options
FORCE_DEBS=0
FORCE_EBIN=0
FORCE_RPIZ=0
SKIP_DEBS=0
SKIP_EBIN=0
SKIP_RPIZ=0
WIFI_SSID=""
WIFI_PSK=""

# ── Usage ─────────────────────────────────────────────────────────────────────
usage() {
    cat << EOF
SecuBox Eye Remote — Full Build Pipeline v${VERSION}

Build complete Eye Remote system:
  1. SecuBox .deb packages
  2. ESPRESSObin firmware with slipstreamed modules
  3. Pi Zero SD image with embedded ESPRESSObin storage

Usage: sudo $0 [OPTIONS]

STAGES:
  --only-debs           Only build .deb packages
  --only-ebin           Only build ESPRESSObin storage image
  --only-rpiz           Only build Pi Zero SD image
  --skip-debs           Skip .deb building (use existing)
  --skip-ebin           Skip ESPRESSObin image building
  --skip-rpiz           Skip Pi Zero image building

REBUILD:
  --force-debs          Force rebuild all .deb packages
  --force-ebin          Force rebuild ESPRESSObin image
  --force-rpiz          Force rebuild Pi Zero image
  --force               Force rebuild everything

INPUTS:
  --ebin-source PATH    ESPRESSObin base image (default: board/secubox-espressobin-v7-bookworm.img.gz)
  --rpiz-source PATH    RPi OS Lite image (.img or .img.xz)
                        (auto-downloads if not specified)

OUTPUTS:
  --output DIR          Output directory (default: ./output)
  --ebin-storage PATH   ESPRESSObin storage image output
  --rpiz-sd PATH        Pi Zero SD image output

WIFI (optional):
  --wifi SSID:PSK       Pre-configure WiFi (e.g., --wifi "MyNetwork:password")

EXAMPLES:
  # Full build (auto-detects what needs rebuilding)
  sudo $0

  # Force rebuild everything
  sudo $0 --force

  # Only rebuild ESPRESSObin storage with existing debs
  sudo $0 --only-ebin

  # Build Pi Zero image with WiFi
  sudo $0 --wifi "SecuBox-Net:MyPassword"

  # Use custom RPi OS image
  sudo $0 --rpiz-source ~/Downloads/raspios-lite.img.xz

EOF
    exit 0
}

# ── Parse arguments ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --only-debs)      SKIP_EBIN=1; SKIP_RPIZ=1; shift ;;
        --only-ebin)      SKIP_DEBS=1; SKIP_RPIZ=1; shift ;;
        --only-rpiz)      SKIP_DEBS=1; SKIP_EBIN=1; shift ;;
        --skip-debs)      SKIP_DEBS=1; shift ;;
        --skip-ebin)      SKIP_EBIN=1; shift ;;
        --skip-rpiz)      SKIP_RPIZ=1; shift ;;
        --force-debs)     FORCE_DEBS=1; shift ;;
        --force-ebin)     FORCE_EBIN=1; shift ;;
        --force-rpiz)     FORCE_RPIZ=1; shift ;;
        --force)          FORCE_DEBS=1; FORCE_EBIN=1; FORCE_RPIZ=1; shift ;;
        --ebin-source)    EBIN_SOURCE="$2"; shift 2 ;;
        --rpiz-source)    RPIZ_SOURCE="$2"; shift 2 ;;
        --output)         OUTPUT_DIR="$2"; DEBS_DIR="$2/debs"; shift 2 ;;
        --ebin-storage)   EBIN_STORAGE_IMG="$2"; shift 2 ;;
        --rpiz-sd)        RPIZ_SD_IMG="$2"; shift 2 ;;
        --wifi)
            IFS=':' read -r WIFI_SSID WIFI_PSK <<< "$2"
            shift 2
            ;;
        --help|-h) usage ;;
        *) err "Unknown option: $1" ;;
    esac
done

# ── Prerequisites ─────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && err "This script must be run as root (sudo)"

check_deps() {
    local missing=()
    for cmd in debootstrap parted mkfs.fat mkfs.ext4 qemu-aarch64-static rsync; do
        command -v "$cmd" >/dev/null || missing+=("$cmd")
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        warn "Missing dependencies: ${missing[*]}"
        log "Installing..."
        apt-get update -qq
        apt-get install -y -qq debootstrap parted dosfstools qemu-user-static rsync
    fi
}

check_deps

mkdir -p "$OUTPUT_DIR" "$DEBS_DIR" "$CACHE_DIR"

# ══════════════════════════════════════════════════════════════════════════════
# BANNER
# ══════════════════════════════════════════════════════════════════════════════

echo -e "${PURPLE}${BOLD}"
cat << 'BANNER'
 ╔═══════════════════════════════════════════════════════════════════════════╗
 ║                                                                           ║
 ║   ███████╗███████╗ ██████╗██╗   ██╗██████╗  ██████╗ ██╗  ██╗             ║
 ║   ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔═══██╗╚██╗██╔╝             ║
 ║   ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║ ╚███╔╝              ║
 ║   ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║ ██╔██╗              ║
 ║   ███████║███████╗╚██████╗╚██████╔╝██████╔╝╚██████╔╝██╔╝ ██╗             ║
 ║   ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝             ║
 ║                                                                           ║
 ║         EYE REMOTE — Full Build Pipeline                                  ║
 ║         CyberMind · cybermind.fr                                          ║
 ║                                                                           ║
 ╚═══════════════════════════════════════════════════════════════════════════╝
BANNER
echo -e "${NC}"

log "Version: ${VERSION}"
log "Output:  ${OUTPUT_DIR}"
echo ""

# ══════════════════════════════════════════════════════════════════════════════
# STAGE 1: Build .deb packages
# ══════════════════════════════════════════════════════════════════════════════

build_debs() {
    stage "STAGE 1: Build SecuBox .deb Packages"

    # Check if packages exist
    local existing_count
    existing_count=$(find "$DEBS_DIR" -maxdepth 1 -name "secubox-*.deb" 2>/dev/null | wc -l)

    if [[ $FORCE_DEBS -eq 0 ]] && [[ $existing_count -gt 50 ]]; then
        skip "Found $existing_count packages, skipping (use --force-debs to rebuild)"
        return 0
    fi

    log "Building SecuBox packages..."

    # Use existing build-all.sh script
    if [[ -f "${SCRIPT_DIR}/scripts/build-all.sh" ]]; then
        bash "${SCRIPT_DIR}/scripts/build-all.sh" "$DEBS_DIR"
    else
        # Inline build
        local pkg_dirs
        pkg_dirs=$(find "${SCRIPT_DIR}/packages" -maxdepth 1 -type d -name "secubox-*" | sort)
        local total count=0 failed=0

        total=$(echo "$pkg_dirs" | wc -l)
        log "Building $total packages..."

        for pkg_dir in $pkg_dirs; do
            local pkg
            pkg=$(basename "$pkg_dir")
            count=$((count + 1))

            [[ ! -f "$pkg_dir/debian/control" ]] && continue

            log "[$count/$total] $pkg"
            cd "$pkg_dir"

            if dpkg-buildpackage -us -uc -b > /tmp/build-$pkg.log 2>&1; then
                mv ../*.deb "$DEBS_DIR/" 2>/dev/null || true
                rm -f ../*.buildinfo ../*.changes 2>/dev/null || true
            else
                warn "$pkg failed (see /tmp/build-$pkg.log)"
                failed=$((failed + 1))
            fi
            cd "$SCRIPT_DIR"
        done

        log "Built $((total - failed))/$total packages"
    fi

    # Verify
    local final_count
    final_count=$(find "$DEBS_DIR" -maxdepth 1 -name "secubox-*.deb" 2>/dev/null | wc -l)
    ok "Stage 1 complete: $final_count packages in $DEBS_DIR"
}

# ══════════════════════════════════════════════════════════════════════════════
# STAGE 2: Build ESPRESSObin Storage Image
# ══════════════════════════════════════════════════════════════════════════════

build_ebin() {
    stage "STAGE 2: Build ESPRESSObin Storage Image"

    # Check if today's versioned image already exists
    if [[ $FORCE_EBIN -eq 0 ]] && [[ -f "$EBIN_STORAGE_IMG" ]]; then
        skip "Storage image exists: $(basename "$EBIN_STORAGE_IMG") (use --force-ebin to rebuild)"
        return 0
    fi

    # Also check for any recent image (within 24h) if exact version not found
    if [[ $FORCE_EBIN -eq 0 ]]; then
        local recent_img
        recent_img=$(find "$OUTPUT_DIR" -maxdepth 1 -name "eye-remote-storage-*.img" -mmin -1440 2>/dev/null | head -1)
        if [[ -n "$recent_img" ]]; then
            skip "Recent storage image exists: $(basename "$recent_img") (use --force-ebin to rebuild)"
            EBIN_STORAGE_IMG="$recent_img"
            return 0
        fi
    fi

    # Check source image
    if [[ ! -f "$EBIN_SOURCE" ]]; then
        # Try to find an alternative
        local alt_source
        alt_source=$(find "${SCRIPT_DIR}" -name "*espressobin*bookworm*.img*" 2>/dev/null | head -1)
        if [[ -n "$alt_source" ]]; then
            EBIN_SOURCE="$alt_source"
            log "Using source: $EBIN_SOURCE"
        else
            err "ESPRESSObin source image not found: $EBIN_SOURCE"
        fi
    fi

    # Use build-storage-img.sh if available
    if [[ -f "${SCRIPT_DIR}/remote-ui/round/build-storage-img.sh" ]]; then
        log "Building ESPRESSObin storage image with slipstreamed modules..."
        bash "${SCRIPT_DIR}/remote-ui/round/build-storage-img.sh" \
            --source "$EBIN_SOURCE" \
            --output "$EBIN_STORAGE_IMG" \
            --debs "$DEBS_DIR"
    else
        err "build-storage-img.sh not found"
    fi

    ok "Stage 2 complete: $EBIN_STORAGE_IMG"
}

# ══════════════════════════════════════════════════════════════════════════════
# STAGE 3: Build Pi Zero SD Image with Embedded Storage
# ══════════════════════════════════════════════════════════════════════════════

download_rpios() {
    local url="https://downloads.raspberrypi.com/raspios_lite_armhf/images/raspios_lite_armhf-2024-03-15/2024-03-15-raspios-bookworm-armhf-lite.img.xz"
    local filename="raspios-bookworm-armhf-lite.img.xz"
    local target="${CACHE_DIR}/${filename}"

    if [[ -f "$target" ]]; then
        log "Using cached RPi OS image: $target"
        RPIZ_SOURCE="$target"
        return 0
    fi

    log "Downloading RPi OS Lite..."
    wget -q --show-progress -O "$target" "$url" || {
        warn "Download failed, trying alternative URL..."
        # Try alternative
        url="https://downloads.raspberrypi.org/raspios_lite_armhf_latest"
        wget -q --show-progress -O "$target" "$url" || err "Failed to download RPi OS"
    }

    RPIZ_SOURCE="$target"
    ok "Downloaded: $target"
}

build_rpiz() {
    stage "STAGE 3: Build Pi Zero SD Image"

    # Check if today's versioned image already exists
    if [[ $FORCE_RPIZ -eq 0 ]] && [[ -f "$RPIZ_SD_IMG" ]]; then
        skip "Pi Zero image exists: $(basename "$RPIZ_SD_IMG") (use --force-rpiz to rebuild)"
        return 0
    fi

    # Also check for any recent image (within 24h) if exact version not found
    if [[ $FORCE_RPIZ -eq 0 ]]; then
        local recent_img
        recent_img=$(find "$OUTPUT_DIR" -maxdepth 1 -name "secubox-eye-remote-*.img" -mmin -1440 2>/dev/null | head -1)
        if [[ -n "$recent_img" ]]; then
            skip "Recent Pi Zero image exists: $(basename "$recent_img") (use --force-rpiz to rebuild)"
            RPIZ_SD_IMG="$recent_img"
            return 0
        fi
    fi

    # Get RPi OS source image
    if [[ -z "$RPIZ_SOURCE" ]] || [[ ! -f "$RPIZ_SOURCE" ]]; then
        download_rpios
    fi

    # Verify storage image exists - check both versioned and symlink
    if [[ ! -f "$EBIN_STORAGE_IMG" ]]; then
        # Try symlink or find recent storage image
        if [[ -f "$EBIN_STORAGE_LATEST" ]]; then
            EBIN_STORAGE_IMG="$EBIN_STORAGE_LATEST"
        else
            local found_storage
            found_storage=$(find "$OUTPUT_DIR" -maxdepth 1 -name "eye-remote-storage-*.img" 2>/dev/null | head -1)
            if [[ -n "$found_storage" ]]; then
                EBIN_STORAGE_IMG="$found_storage"
            else
                err "ESPRESSObin storage image not found (run stage 2 first)"
            fi
        fi
    fi
    log "Using storage image: $(basename "$EBIN_STORAGE_IMG")"

    log "Building Pi Zero SD image with embedded ESPRESSObin storage..."

    # Use build-eye-remote-image.sh
    if [[ -f "${SCRIPT_DIR}/remote-ui/round/build-eye-remote-image.sh" ]]; then
        local wifi_args=""
        if [[ -n "$WIFI_SSID" ]]; then
            wifi_args="-s $WIFI_SSID -p $WIFI_PSK"
        fi

        # Build the base image
        bash "${SCRIPT_DIR}/remote-ui/round/build-eye-remote-image.sh" \
            -i "$RPIZ_SOURCE" \
            -o "$OUTPUT_DIR" \
            $wifi_args \
            --framebuffer

        # Find the generated image
        local built_img
        built_img=$(find "$OUTPUT_DIR" -name "secubox-eye-remote-*.img" -newer /tmp 2>/dev/null | head -1)

        if [[ -z "$built_img" ]]; then
            built_img="${OUTPUT_DIR}/secubox-eye-remote-2.2.0.img"
        fi

        if [[ -f "$built_img" ]]; then
            # Now embed the ESPRESSObin storage image
            embed_storage_in_rpiz "$built_img"
            mv "$built_img" "$RPIZ_SD_IMG"
        else
            err "Pi Zero image build failed"
        fi
    else
        err "build-eye-remote-image.sh not found"
    fi

    ok "Stage 3 complete: $RPIZ_SD_IMG"
}

embed_storage_in_rpiz() {
    local rpiz_img="$1"

    log "Embedding ESPRESSObin storage image into Pi Zero SD..."

    # Mount Pi Zero rootfs
    local loop_dev mount_point
    loop_dev=$(losetup --find --show --partscan "$rpiz_img")
    mount_point=$(mktemp -d)

    # Wait for partitions
    sleep 1

    mount "${loop_dev}p2" "$mount_point"

    # Create storage directory and copy the storage image
    mkdir -p "$mount_point/var/lib/secubox/eye-remote"
    log "Copying storage.img ($(du -h "$EBIN_STORAGE_IMG" | cut -f1))..."
    cp "$EBIN_STORAGE_IMG" "$mount_point/var/lib/secubox/eye-remote/storage.img"

    # Update gadget service to use storage mode by default
    if [[ -f "$mount_point/etc/systemd/system/secubox-eye-gadget.service" ]]; then
        sed -i 's|gadget-setup.sh up|gadget-setup.sh storage|g' \
            "$mount_point/etc/systemd/system/secubox-eye-gadget.service"
    fi

    # Create a SecuBox banner for the console
    cat > "$mount_point/etc/motd" << 'MOTD'

  ╔═══════════════════════════════════════════════════════════════════════╗
  ║                                                                       ║
  ║   ███████╗███████╗ ██████╗██╗   ██╗██████╗  ██████╗ ██╗  ██╗         ║
  ║   ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔═══██╗╚██╗██╔╝         ║
  ║   ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║ ╚███╔╝          ║
  ║   ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║ ██╔██╗          ║
  ║   ███████║███████╗╚██████╗╚██████╔╝██████╔╝╚██████╔╝██╔╝ ██╗         ║
  ║   ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝         ║
  ║                                                                       ║
  ║                 EYE REMOTE — Pi Zero W                                ║
  ║                 CyberMind · cybermind.fr                              ║
  ║                                                                       ║
  ╠═══════════════════════════════════════════════════════════════════════╣
  ║                                                                       ║
  ║   USB OTG Storage:   /var/lib/secubox/eye-remote/storage.img         ║
  ║   HyperPixel 2.1:    480x480 Round Touch                              ║
  ║                                                                       ║
  ║   Credentials:       pi / raspberry                                  ║
  ║                                                                       ║
  ║   Gadget commands:                                                    ║
  ║     sudo /etc/secubox/eye-remote/gadget-setup.sh storage  # USB boot ║
  ║     sudo /etc/secubox/eye-remote/gadget-setup.sh up       # Full OTG ║
  ║     sudo /etc/secubox/eye-remote/gadget-setup.sh status   # Status   ║
  ║                                                                       ║
  ╚═══════════════════════════════════════════════════════════════════════╝

MOTD

    sync
    umount "$mount_point"
    losetup -d "$loop_dev"
    rm -rf "$mount_point"

    ok "Storage image embedded"
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

START_TIME=$(date +%s)

# Stage 1: Build .deb packages
if [[ $SKIP_DEBS -eq 0 ]]; then
    build_debs
else
    skip "Stage 1: .deb packages (--skip-debs)"
fi

# Stage 2: Build ESPRESSObin storage image
if [[ $SKIP_EBIN -eq 0 ]]; then
    build_ebin
else
    skip "Stage 2: ESPRESSObin storage (--skip-ebin)"
fi

# Stage 3: Build Pi Zero SD image
if [[ $SKIP_RPIZ -eq 0 ]]; then
    build_rpiz
else
    skip "Stage 3: Pi Zero SD image (--skip-rpiz)"
fi

# ══════════════════════════════════════════════════════════════════════════════
# CREATE SYMLINKS TO LATEST
# ══════════════════════════════════════════════════════════════════════════════

if [[ -f "$EBIN_STORAGE_IMG" ]]; then
    ln -sf "$(basename "$EBIN_STORAGE_IMG")" "$EBIN_STORAGE_LATEST"
    log "Symlink: $(basename "$EBIN_STORAGE_LATEST") → $(basename "$EBIN_STORAGE_IMG")"
fi

if [[ -f "$RPIZ_SD_IMG" ]]; then
    ln -sf "$(basename "$RPIZ_SD_IMG")" "$RPIZ_SD_LATEST"
    log "Symlink: $(basename "$RPIZ_SD_LATEST") → $(basename "$RPIZ_SD_IMG")"
fi

# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo ""
echo -e "${GREEN}${BOLD}"
cat << 'DONE'
 ╔═══════════════════════════════════════════════════════════════════════════╗
 ║                        BUILD COMPLETE                                     ║
 ╚═══════════════════════════════════════════════════════════════════════════╝
DONE
echo -e "${NC}"

echo "  Version:    ${VERSION}"
echo "  Build date: ${BUILD_DATE}"
echo "  Build time: $((ELAPSED / 60))m $((ELAPSED % 60))s"
echo ""
echo "  Outputs:"

if [[ -d "$DEBS_DIR" ]]; then
    deb_count=$(find "$DEBS_DIR" -maxdepth 1 -name "secubox-*.deb" 2>/dev/null | wc -l)
    echo "    📦 Packages:     $DEBS_DIR ($deb_count debs)"
fi

if [[ -f "$EBIN_STORAGE_IMG" ]]; then
    echo "    💾 EBin Storage: $(basename "$EBIN_STORAGE_IMG") ($(du -h "$EBIN_STORAGE_IMG" | cut -f1))"
    echo "                     → $EBIN_STORAGE_LATEST"
fi

if [[ -f "$RPIZ_SD_IMG" ]]; then
    echo "    🔴 Pi Zero SD:   $(basename "$RPIZ_SD_IMG") ($(du -h "$RPIZ_SD_IMG" | cut -f1))"
    echo "                     → $RPIZ_SD_LATEST"
fi

echo ""
echo "  All outputs in: $OUTPUT_DIR"
echo ""
echo "  Next steps:"
echo ""
echo "    1. Flash Pi Zero SD card:"
echo "       sudo dd if=$RPIZ_SD_LATEST of=/dev/sdX bs=4M status=progress"
echo ""
echo "    2. Insert SD into Pi Zero W + HyperPixel 2.1 Round"
echo ""
echo "    3. Connect Pi Zero USB DATA port to ESPRESSObin USB"
echo ""
echo "    4. Boot ESPRESSObin from USB storage:"
echo "       U-Boot> usb start"
echo "       U-Boot> run bootcmd_usb0"
echo ""
echo "  Credentials:"
echo "    Pi Zero:     pi / raspberry"
echo "    ESPRESSObin: root / secubox"
echo ""
