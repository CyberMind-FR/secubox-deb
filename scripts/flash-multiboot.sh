#!/usr/bin/env bash
# SecuBox-DEB :: flash-multiboot.sh
# Download and flash latest multiboot image to USB
# CyberMind — Gérald Kerma
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
readonly CACHE_DIR="${PROJECT_DIR}/output/cache"
readonly REPO="CyberMind-FR/secubox-deb"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()   { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

usage() {
    cat <<EOF
SecuBox Multiboot Flash Tool

Usage: $(basename "$0") [OPTIONS] [DEVICE]

Download the latest multiboot image and flash to USB drive.

Arguments:
  DEVICE          USB device to flash (e.g., /dev/sdb)
                  If not provided, lists available devices

Options:
  -l, --list        List available releases
  -r, --release TAG Download specific release (e.g., multiboot-v2.2.4-live)
  -d, --download    Download only, don't flash
  -f, --force       Skip confirmation prompts
  -c, --clean       Remove cached files after flashing
  -h, --help        Show this help message

Examples:
  # List releases
  $(basename "$0") --list

  # Flash to /dev/sdb (interactive)
  $(basename "$0") /dev/sdb

  # Download specific release without flashing
  $(basename "$0") --release multiboot-v2.2.4-live --download

  # Flash with force (no confirmation)
  $(basename "$0") --force /dev/sdb

Requirements:
  - gh (GitHub CLI) - authenticated
  - xz (for decompression)
  - dd (for flashing)
  - Root privileges (for flashing)

EOF
    exit "${1:-0}"
}

check_deps() {
    local missing=()
    for cmd in gh xz dd; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        error "Missing dependencies: ${missing[*]}"
        exit 1
    fi

    # Check gh auth
    if ! gh auth status &>/dev/null; then
        error "GitHub CLI not authenticated. Run: gh auth login"
        exit 1
    fi
}

list_releases() {
    log "Available multiboot releases:"
    echo
    gh release list --repo "$REPO" --limit 10 | grep -i multiboot || {
        warn "No multiboot releases found"
        echo
        log "All releases:"
        gh release list --repo "$REPO" --limit 5
    }
}

list_devices() {
    log "Available USB devices:"
    echo
    lsblk -d -o NAME,SIZE,MODEL,TRAN | grep -E "^NAME|usb" || {
        warn "No USB devices found"
        lsblk -d -o NAME,SIZE,MODEL,TRAN
    }
}

get_latest_multiboot() {
    gh release list --repo "$REPO" --limit 20 --json tagName,isPrerelease \
        --jq '.[] | select(.tagName | contains("multiboot")) | .tagName' \
        | head -1
}

download_image() {
    local tag="$1"
    local dest_dir="$2"

    mkdir -p "$dest_dir"

    log "Fetching release info for: $tag"

    # Get asset names
    local assets
    assets=$(gh release view "$tag" --repo "$REPO" --json assets --jq '.assets[].name')

    local img_file sha_file
    img_file=$(echo "$assets" | grep -E '\.img\.xz$' | head -1)
    sha_file=$(echo "$assets" | grep -E '\.sha256$' | head -1)

    if [[ -z "$img_file" ]]; then
        error "No .img.xz file found in release $tag"
        exit 1
    fi

    local img_path="${dest_dir}/${img_file}"
    local sha_path="${dest_dir}/${sha_file}"

    # Download if not cached
    if [[ -f "$img_path" ]]; then
        log "Image already cached: $img_path"
    else
        log "Downloading: $img_file"
        gh release download "$tag" --repo "$REPO" --pattern "$img_file" --dir "$dest_dir"
    fi

    # Download checksum
    if [[ -n "$sha_file" ]]; then
        log "Downloading checksum: $sha_file"
        gh release download "$tag" --repo "$REPO" --pattern "$sha_file" --dir "$dest_dir" --clobber

        # Verify checksum
        log "Verifying checksum..."
        (cd "$dest_dir" && sha256sum -c "$sha_file") || {
            error "Checksum verification failed!"
            exit 1
        }
        log "Checksum OK"
    fi

    echo "$img_path"
}

flash_image() {
    local img_xz="$1"
    local device="$2"
    local force="${3:-false}"

    # Validate device
    if [[ ! -b "$device" ]]; then
        error "Not a block device: $device"
        exit 1
    fi

    # Check if mounted
    if mount | grep -q "^${device}"; then
        error "Device $device has mounted partitions. Unmount first."
        mount | grep "^${device}"
        exit 1
    fi

    # Get device info
    local dev_info
    dev_info=$(lsblk -d -o NAME,SIZE,MODEL "$device" 2>/dev/null | tail -1)

    # Confirmation
    if [[ "$force" != "true" ]]; then
        echo
        echo -e "${RED}╔════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║  WARNING: ALL DATA ON THIS DEVICE WILL BE DESTROYED!       ║${NC}"
        echo -e "${RED}╚════════════════════════════════════════════════════════════╝${NC}"
        echo
        echo "Device: $device"
        echo "Info:   $dev_info"
        echo "Image:  $(basename "$img_xz")"
        echo
        read -rp "Type 'YES' to confirm: " confirm
        if [[ "$confirm" != "YES" ]]; then
            error "Aborted by user"
            exit 1
        fi
    fi

    # Flash
    log "Flashing to $device..."
    log "This may take several minutes..."

    # Use pv if available for progress, otherwise dd status
    if command -v pv &>/dev/null; then
        xz -dc "$img_xz" | pv | sudo dd of="$device" bs=4M conv=fsync status=none
    else
        xz -dc "$img_xz" | sudo dd of="$device" bs=4M conv=fsync status=progress
    fi

    # Sync
    log "Syncing..."
    sync

    log "Flash complete!"
    echo
    log "Device partitions:"
    lsblk "$device"
}

main() {
    local release=""
    local device=""
    local download_only=false
    local force=false
    local clean=false
    local list=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help) usage 0 ;;
            -l|--list) list=true; shift ;;
            -r|--release) release="$2"; shift 2 ;;
            -d|--download) download_only=true; shift ;;
            -f|--force) force=true; shift ;;
            -c|--clean) clean=true; shift ;;
            -*) error "Unknown option: $1"; usage 1 ;;
            *) device="$1"; shift ;;
        esac
    done

    check_deps

    # List mode
    if [[ "$list" == "true" ]]; then
        list_releases
        exit 0
    fi

    # Get release
    if [[ -z "$release" ]]; then
        release=$(get_latest_multiboot)
        if [[ -z "$release" ]]; then
            error "No multiboot release found"
            exit 1
        fi
        log "Latest multiboot release: $release"
    fi

    # Download
    local img_path
    img_path=$(download_image "$release" "$CACHE_DIR")

    if [[ "$download_only" == "true" ]]; then
        log "Download complete: $img_path"
        exit 0
    fi

    # Need device for flashing
    if [[ -z "$device" ]]; then
        echo
        list_devices
        echo
        error "No device specified. Use: $(basename "$0") /dev/sdX"
        exit 1
    fi

    # Check root for flashing
    if [[ $EUID -ne 0 ]] && ! sudo -n true 2>/dev/null; then
        warn "Root privileges required for flashing"
    fi

    # Flash
    flash_image "$img_path" "$device" "$force"

    # Clean cache
    if [[ "$clean" == "true" ]]; then
        log "Cleaning cache..."
        rm -f "$img_path" "${img_path%.img.xz}.sha256"
    fi

    echo
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  SecuBox Multiboot USB Ready!                              ║${NC}"
    echo -e "${GREEN}║  Boot from USB to start SecuBox Live                       ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
}

main "$@"
