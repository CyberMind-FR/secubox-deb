#!/usr/bin/env bash
# SecuBox-Deb :: QEMU ARM64 VM Creator
# Creates and runs ARM64 VMs using QEMU emulation on x86_64 hosts
# CyberMind — Gerald Kerma
set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly DEFAULT_RAM="4096"
readonly DEFAULT_CPUS="4"
readonly DEFAULT_DISK_SIZE="8G"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${BLUE}[INFO    ]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK      ]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN    ]${NC} $*"; }
fail() { echo -e "${RED}[FAIL    ]${NC} $*" >&2; exit 1; }

usage() {
    cat <<EOF
Usage: $0 [OPTIONS] <image.img|image.img.gz>

Creates and runs a QEMU ARM64 virtual machine from a SecuBox image.

Options:
  --ram SIZE       RAM size in MB (default: ${DEFAULT_RAM})
  --cpus N         Number of CPU cores (default: ${DEFAULT_CPUS})
  --name NAME      VM name (default: secubox-arm64)
  --convert        Convert .img to qcow2 format (faster I/O)
  --no-gui         Run headless (serial console only)
  --ssh-port PORT  Forward SSH to host port (default: 2222)
  --http-port PORT Forward HTTP to host port (default: 8080)
  --help           Show this help

Examples:
  $0 output/secubox-espressobin-v7-bookworm.img.gz
  $0 --ram 2048 --cpus 2 --no-gui secubox-arm64.img
  $0 --convert --ssh-port 2223 secubox-arm64.img

Requirements:
  - qemu-system-aarch64
  - qemu-efi-aarch64 (UEFI firmware)

Notes:
  - ARM64 emulation on x86 is SLOW (10-20x slower than native)
  - For faster ARM testing, use real ARM hardware or ARM64 cloud VMs
  - SSH: ssh -p 2222 root@localhost
  - Web: http://localhost:8080
EOF
    exit 0
}

# Parse arguments
RAM="${DEFAULT_RAM}"
CPUS="${DEFAULT_CPUS}"
VM_NAME="secubox-arm64"
CONVERT=0
NO_GUI=0
SSH_PORT="2222"
HTTP_PORT="8080"
IMAGE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ram)      RAM="$2"; shift 2 ;;
        --cpus)     CPUS="$2"; shift 2 ;;
        --name)     VM_NAME="$2"; shift 2 ;;
        --convert)  CONVERT=1; shift ;;
        --no-gui)   NO_GUI=1; shift ;;
        --ssh-port) SSH_PORT="$2"; shift 2 ;;
        --http-port) HTTP_PORT="$2"; shift 2 ;;
        --help|-h)  usage ;;
        -*)         fail "Unknown option: $1" ;;
        *)          IMAGE="$1"; shift ;;
    esac
done

[[ -z "$IMAGE" ]] && usage

# Check dependencies
command -v qemu-system-aarch64 >/dev/null || fail "qemu-system-aarch64 not found. Install: apt install qemu-system-arm"

# Find UEFI firmware (prefer AAVMF which has consistent 64MB size)
UEFI_CODE=""
UEFI_VARS_TEMPLATE=""
for path in /usr/share/AAVMF/AAVMF_CODE.fd \
            /usr/share/edk2/aarch64/QEMU_EFI.fd \
            /usr/share/qemu-efi-aarch64/QEMU_EFI.fd; do
    if [[ -f "$path" ]]; then
        UEFI_CODE="$path"
        # Get matching VARS template if AAVMF
        if [[ "$path" == *AAVMF* ]]; then
            UEFI_VARS_TEMPLATE="${path%_CODE.fd}_VARS.fd"
        fi
        break
    fi
done
[[ -z "$UEFI_CODE" ]] && fail "UEFI firmware not found. Install: apt install qemu-efi-aarch64 ovmf"

# Prepare image
log "Preparing image: $IMAGE"

if [[ "$IMAGE" == *.gz ]]; then
    log "Decompressing image..."
    WORK_IMG="${IMAGE%.gz}"
    if [[ ! -f "$WORK_IMG" ]] || [[ "$IMAGE" -nt "$WORK_IMG" ]]; then
        gunzip -k "$IMAGE"
    fi
    IMAGE="$WORK_IMG"
fi

if [[ ! -f "$IMAGE" ]]; then
    fail "Image not found: $IMAGE"
fi

# Convert to qcow2 if requested
if [[ $CONVERT -eq 1 ]]; then
    QCOW2="${IMAGE%.img}.qcow2"
    if [[ ! -f "$QCOW2" ]] || [[ "$IMAGE" -nt "$QCOW2" ]]; then
        log "Converting to qcow2 format..."
        qemu-img convert -f raw -O qcow2 "$IMAGE" "$QCOW2"
        ok "Created: $QCOW2"
    fi
    IMAGE="$QCOW2"
fi

# Create UEFI vars file (writable copy)
VARS_FILE="/tmp/${VM_NAME}-uefi-vars.fd"
if [[ ! -f "$VARS_FILE" ]] || [[ $(stat -c%s "$VARS_FILE") -ne $(stat -c%s "$UEFI_CODE") ]]; then
    if [[ -n "$UEFI_VARS_TEMPLATE" ]] && [[ -f "$UEFI_VARS_TEMPLATE" ]]; then
        cp "$UEFI_VARS_TEMPLATE" "$VARS_FILE"
        log "Using UEFI vars template: $UEFI_VARS_TEMPLATE"
    else
        # Create file matching firmware size
        truncate -s "$(stat -c%s "$UEFI_CODE")" "$VARS_FILE"
    fi
fi

# Build QEMU command
QEMU_CMD=(
    qemu-system-aarch64
    -name "$VM_NAME"
    -machine virt,gic-version=3
    -cpu cortex-a72
    -smp "$CPUS"
    -m "$RAM"

    # UEFI firmware
    -drive "if=pflash,format=raw,file=$UEFI_CODE,readonly=on"
    -drive "if=pflash,format=raw,file=$VARS_FILE"

    # Boot disk
    -drive "if=virtio,format=$(qemu-img info --output=json "$IMAGE" | jq -r '.format'),file=$IMAGE"

    # Network with port forwarding
    -netdev "user,id=net0,hostfwd=tcp::${SSH_PORT}-:22,hostfwd=tcp::${HTTP_PORT}-:80,hostfwd=tcp::$((HTTP_PORT+363))-:443"
    -device virtio-net-pci,netdev=net0

    # RNG for faster boot
    -device virtio-rng-pci

    # Serial console
    -serial mon:stdio
)

# Display options
if [[ $NO_GUI -eq 1 ]]; then
    QEMU_CMD+=(-nographic)
    log "Running headless (serial console)"
else
    QEMU_CMD+=(-device virtio-gpu-pci -display gtk)
    log "Running with GUI display"
fi

ok "Configuration:"
echo "  RAM: ${RAM}MB"
echo "  CPUs: ${CPUS}"
echo "  Image: $IMAGE"
echo "  SSH: localhost:${SSH_PORT}"
echo "  HTTP: localhost:${HTTP_PORT}"
echo "  HTTPS: localhost:$((HTTP_PORT+363))"
echo ""

warn "ARM64 emulation is slow (~10-20x slower than native)"
log "Starting QEMU..."
echo "---"

exec "${QEMU_CMD[@]}"
