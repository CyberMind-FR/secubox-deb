#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  SecuBox-DEB :: partition-overlay.sh v1.0
#  Create GPT partition layout for overlay installer
#  CyberMind — https://cybermind.fr
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

readonly SCRIPT_NAME="partition-overlay"
readonly VERSION="1.0.0"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log()  { echo -e "${CYAN}[partition]${NC} $*"; }
ok()   { echo -e "${GREEN}[  OK  ]${NC} $*"; }
warn() { echo -e "${YELLOW}[ WARN ]${NC} $*"; }
err()  { echo -e "${RED}[FAIL  ]${NC} $*" >&2; exit 1; }

usage() {
    cat << EOF
${BOLD}SecuBox Overlay Partition Layout v${VERSION}${NC}

Creates the multi-layer overlay partition scheme for SecuBox v1.6.7.2+

${BOLD}USAGE:${NC}
    $SCRIPT_NAME --device <DEVICE> [OPTIONS]

${BOLD}OPTIONS:${NC}
    -d, --device DEV    Target device (e.g., /dev/sda, /dev/nvme0n1)
    -s, --size SIZE     Total image size (default: auto-detect)
    --system-size SIZE  System partition size (default: 2G)
    --config-size SIZE  Config partition size (default: 512M)
    --data-size SIZE    Data partition size (default: 2G)
    --snap-size SIZE    Snapshots partition size (default: 1G)
    --swap-size SIZE    Swap partition size (default: 512M)
    --dry-run           Show partition layout without creating
    -h, --help          Show this help

${BOLD}PARTITION LAYOUT:${NC}
    ┌─────────────────────────────────────────────────────────────┐
    │ ESP (512MB)      │ GRUB + EFI + boot config                 │
    │ SYSTEM (2GB)     │ SquashFS (read-only base)                │
    │ CONFIG (512MB)   │ ext4 - /etc/secubox, nginx, systemd      │
    │ DATA (2GB)       │ ext4 - /var/lib/secubox, logs, certs     │
    │ SNAPSHOTS (1GB)  │ ext4 - versioned config/data backups     │
    │ SWAP (512MB)     │ swap - RAM extension when needed         │
    └─────────────────────────────────────────────────────────────┘

${BOLD}EXAMPLES:${NC}
    # Partition a USB drive
    $SCRIPT_NAME --device /dev/sdb

    # Partition with custom sizes
    $SCRIPT_NAME --device /dev/nvme0n1 --data-size 4G --snap-size 2G

    # Preview layout without changes
    $SCRIPT_NAME --device /dev/sda --dry-run

EOF
    exit 0
}

# Defaults
DEVICE=""
SYSTEM_SIZE="2G"
CONFIG_SIZE="512M"
DATA_SIZE="2G"
SNAP_SIZE="1G"
SWAP_SIZE="512M"
ESP_SIZE="512M"
DRY_RUN=0

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--device)      DEVICE="$2"; shift 2 ;;
        -s|--size)        shift 2 ;; # Ignored, auto-calculate
        --system-size)    SYSTEM_SIZE="$2"; shift 2 ;;
        --config-size)    CONFIG_SIZE="$2"; shift 2 ;;
        --data-size)      DATA_SIZE="$2"; shift 2 ;;
        --snap-size)      SNAP_SIZE="$2"; shift 2 ;;
        --swap-size)      SWAP_SIZE="$2"; shift 2 ;;
        --dry-run)        DRY_RUN=1; shift ;;
        -h|--help)        usage ;;
        *) err "Unknown option: $1. Use --help for usage." ;;
    esac
done

# Validation
[[ -z "$DEVICE" ]] && err "Device required. Use --device /dev/sdX"
[[ $EUID -ne 0 ]] && err "Must run as root"

if [[ ! -b "$DEVICE" ]] && [[ $DRY_RUN -eq 0 ]]; then
    err "Device not found: $DEVICE"
fi

# Convert sizes to MiB for parted
size_to_mib() {
    local size="$1"
    local num="${size%[GMK]}"
    local unit="${size: -1}"

    case "$unit" in
        G|g) echo $((num * 1024)) ;;
        M|m) echo "$num" ;;
        K|k) echo $((num / 1024)) ;;
        *)   echo "$size" ;;  # Assume MiB if no unit
    esac
}

ESP_MIB=$(size_to_mib "$ESP_SIZE")
SYSTEM_MIB=$(size_to_mib "$SYSTEM_SIZE")
CONFIG_MIB=$(size_to_mib "$CONFIG_SIZE")
DATA_MIB=$(size_to_mib "$DATA_SIZE")
SNAP_MIB=$(size_to_mib "$SNAP_SIZE")
SWAP_MIB=$(size_to_mib "$SWAP_SIZE")

# Calculate partition boundaries (1 MiB alignment)
P1_START=1           # ESP start
P1_END=$((P1_START + ESP_MIB))
P2_START=$P1_END     # SYSTEM start
P2_END=$((P2_START + SYSTEM_MIB))
P3_START=$P2_END     # CONFIG start
P3_END=$((P3_START + CONFIG_MIB))
P4_START=$P3_END     # DATA start
P4_END=$((P4_START + DATA_MIB))
P5_START=$P4_END     # SNAPSHOTS start
P5_END=$((P5_START + SNAP_MIB))
P6_START=$P5_END     # SWAP start
P6_END=$((P6_START + SWAP_MIB))

TOTAL_MIB=$P6_END
TOTAL_GB=$(echo "scale=2; $TOTAL_MIB / 1024" | bc)

# Display layout
echo ""
echo -e "${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║          SecuBox Overlay Partition Layout                     ║${NC}"
echo -e "${BOLD}╠═══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}║${NC}  Device: ${CYAN}${DEVICE}${NC}"
echo -e "${BOLD}║${NC}  Total:  ${CYAN}${TOTAL_GB} GB${NC} (${TOTAL_MIB} MiB)"
echo -e "${BOLD}╠═══════════════════════════════════════════════════════════════╣${NC}"
printf "${BOLD}║${NC}  %-8s %-12s %-10s %-20s${BOLD}║${NC}\n" "Part" "Size" "Offset" "Purpose"
echo -e "${BOLD}╠═══════════════════════════════════════════════════════════════╣${NC}"
printf "${BOLD}║${NC}  ${GREEN}%-8s${NC} %-12s %-10s %-20s${BOLD}║${NC}\n" "ESP" "${ESP_SIZE}" "${P1_START}MiB" "EFI bootloader"
printf "${BOLD}║${NC}  ${CYAN}%-8s${NC} %-12s %-10s %-20s${BOLD}║${NC}\n" "SYSTEM" "${SYSTEM_SIZE}" "${P2_START}MiB" "SquashFS base"
printf "${BOLD}║${NC}  ${YELLOW}%-8s${NC} %-12s %-10s %-20s${BOLD}║${NC}\n" "CONFIG" "${CONFIG_SIZE}" "${P3_START}MiB" "Persistent config"
printf "${BOLD}║${NC}  ${YELLOW}%-8s${NC} %-12s %-10s %-20s${BOLD}║${NC}\n" "DATA" "${DATA_SIZE}" "${P4_START}MiB" "Persistent data"
printf "${BOLD}║${NC}  ${YELLOW}%-8s${NC} %-12s %-10s %-20s${BOLD}║${NC}\n" "SNAPSHOT" "${SNAP_SIZE}" "${P5_START}MiB" "Version backups"
printf "${BOLD}║${NC}  %-8s %-12s %-10s %-20s${BOLD}║${NC}\n" "SWAP" "${SWAP_SIZE}" "${P6_START}MiB" "RAM extension"
echo -e "${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

if [[ $DRY_RUN -eq 1 ]]; then
    log "DRY RUN: No changes made"
    exit 0
fi

# Confirm
echo -e "${RED}${BOLD}WARNING: ALL DATA ON ${DEVICE} WILL BE DESTROYED!${NC}"
echo ""
read -p "Type 'PARTITION' to confirm: " confirm
[[ "$confirm" != "PARTITION" ]] && err "Cancelled"

# Unmount any existing partitions
log "Unmounting existing partitions..."
for part in "${DEVICE}"*; do
    [[ -b "$part" ]] && umount "$part" 2>/dev/null || true
done

# Create GPT partition table
log "Creating GPT partition table..."
parted -s "$DEVICE" mklabel gpt
ok "GPT table created"

# Create partitions
log "Creating partitions..."

# Partition 1: ESP (EFI System Partition)
parted -s "$DEVICE" mkpart ESP fat32 ${P1_START}MiB ${P1_END}MiB
parted -s "$DEVICE" set 1 esp on
ok "ESP partition created (${ESP_SIZE})"

# Partition 2: SYSTEM (SquashFS)
parted -s "$DEVICE" mkpart SYSTEM ext4 ${P2_START}MiB ${P2_END}MiB
ok "SYSTEM partition created (${SYSTEM_SIZE})"

# Partition 3: CONFIG
parted -s "$DEVICE" mkpart CONFIG ext4 ${P3_START}MiB ${P3_END}MiB
ok "CONFIG partition created (${CONFIG_SIZE})"

# Partition 4: DATA
parted -s "$DEVICE" mkpart DATA ext4 ${P4_START}MiB ${P4_END}MiB
ok "DATA partition created (${DATA_SIZE})"

# Partition 5: SNAPSHOTS
parted -s "$DEVICE" mkpart SNAPSHOTS ext4 ${P5_START}MiB ${P5_END}MiB
ok "SNAPSHOTS partition created (${SNAP_SIZE})"

# Partition 6: SWAP
parted -s "$DEVICE" mkpart SWAP linux-swap ${P6_START}MiB ${P6_END}MiB
ok "SWAP partition created (${SWAP_SIZE})"

# Re-read partition table
partprobe "$DEVICE" 2>/dev/null || true
sleep 2

# Determine partition naming scheme (nvme vs sd)
get_part_name() {
    local base="$1"
    local num="$2"

    if [[ "$base" == *nvme* ]] || [[ "$base" == *mmcblk* ]]; then
        echo "${base}p${num}"
    else
        echo "${base}${num}"
    fi
}

PART_ESP=$(get_part_name "$DEVICE" 1)
PART_SYSTEM=$(get_part_name "$DEVICE" 2)
PART_CONFIG=$(get_part_name "$DEVICE" 3)
PART_DATA=$(get_part_name "$DEVICE" 4)
PART_SNAP=$(get_part_name "$DEVICE" 5)
PART_SWAP=$(get_part_name "$DEVICE" 6)

# Format partitions
log "Formatting partitions..."

mkfs.fat -F32 -n "ESP" "$PART_ESP"
ok "ESP formatted (FAT32)"

# Don't format SYSTEM - it will receive the squashfs image
ok "SYSTEM partition ready (will receive squashfs)"

mkfs.ext4 -L "CONFIG" -q "$PART_CONFIG"
ok "CONFIG formatted (ext4)"

mkfs.ext4 -L "DATA" -q "$PART_DATA"
ok "DATA formatted (ext4)"

mkfs.ext4 -L "SNAPSHOTS" -q "$PART_SNAP"
ok "SNAPSHOTS formatted (ext4)"

mkswap -L "SWAP" "$PART_SWAP"
ok "SWAP formatted"

# Create directory structure on CONFIG and DATA
log "Creating directory structure..."

MNT_CONFIG="/mnt/secubox-config-$$"
MNT_DATA="/mnt/secubox-data-$$"
MNT_SNAP="/mnt/secubox-snap-$$"

mkdir -p "$MNT_CONFIG" "$MNT_DATA" "$MNT_SNAP"

mount "$PART_CONFIG" "$MNT_CONFIG"
mount "$PART_DATA" "$MNT_DATA"
mount "$PART_SNAP" "$MNT_SNAP"

# CONFIG structure
mkdir -p "$MNT_CONFIG"/{etc/secubox,etc/nginx,etc/systemd,etc/ssh}
mkdir -p "$MNT_CONFIG"/home

# DATA structure
mkdir -p "$MNT_DATA"/{var/lib/secubox,var/log/secubox,var/cache/secubox}
mkdir -p "$MNT_DATA"/{etc/secubox/tls,srv/secubox}

# SNAPSHOTS structure
mkdir -p "$MNT_SNAP"/snapshots

# Create metadata file
cat > "$MNT_CONFIG/.overlay-version" << EOF
{
    "version": "1.6.7.2",
    "created": "$(date -Iseconds)",
    "layout": "overlay-v1",
    "partitions": {
        "esp": "$PART_ESP",
        "system": "$PART_SYSTEM",
        "config": "$PART_CONFIG",
        "data": "$PART_DATA",
        "snapshots": "$PART_SNAP",
        "swap": "$PART_SWAP"
    }
}
EOF

ok "Directory structure created"

# Unmount
umount "$MNT_CONFIG"
umount "$MNT_DATA"
umount "$MNT_SNAP"
rmdir "$MNT_CONFIG" "$MNT_DATA" "$MNT_SNAP"

# Display result
echo ""
echo -e "${GREEN}${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║          Partitioning Complete!                               ║${NC}"
echo -e "${GREEN}${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Partitions created:"
lsblk "$DEVICE" -o NAME,SIZE,FSTYPE,LABEL
echo ""
echo "Next steps:"
echo "  1. Write squashfs to SYSTEM partition: dd if=filesystem.squashfs of=$PART_SYSTEM"
echo "  2. Install bootloader to ESP"
echo "  3. Boot from device"
echo ""
