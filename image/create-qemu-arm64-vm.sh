#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

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
# Not fatal here: a Raspberry Pi image boots without any firmware at all,
# and the UEFI branch below re-checks this at the point where it matters.
if [[ -z "$UEFI_CODE" ]]; then
    warn "UEFI firmware not found (fine for Raspberry Pi images)"
fi

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

# ── Boot mode: UEFI, or direct-kernel for Raspberry Pi images ─────────────
#
# A Raspberry Pi image has NO UEFI. It boots through the proprietary Pi
# firmware (config.txt + start4.elf), which `-machine virt` does not provide,
# and which QEMU cannot emulate for a Pi 4/400 at all (its newest raspi
# machine is raspi3b). Handing such an image to the pflash path drops the VM
# into the EFI shell with no explanation — which reads exactly like "the
# image is broken" when the image is perfectly fine.
#
# So: look for an EFI bootloader inside the FAT partition. When there is
# none, pull the kernel and initrd straight out of the image and boot them
# directly. That validates the whole userspace — packages, services, network
# — which is what local validation is for. It does NOT validate the Pi boot
# chain; only real hardware can do that.
BOOT_MODE=uefi
KERNEL_FILE=""
INITRD_FILE=""

if command -v mdir >/dev/null 2>&1 && command -v partx >/dev/null 2>&1; then
    p1_start=$(partx -g -o START -n 1 "$IMAGE" 2>/dev/null | tr -d ' ' || true)
    if [[ -n "$p1_start" ]]; then
        p1_off=$(( p1_start * 512 ))
        if ! mdir -i "${IMAGE}@@${p1_off}" ::/EFI >/dev/null 2>&1; then
            BOOT_MODE=direct
            EXTRACT_DIR="/tmp/${VM_NAME}-boot"
            mkdir -p "$EXTRACT_DIR"
            log "No EFI bootloader found — Raspberry Pi image, using direct kernel boot"
            for f in vmlinuz initrd.img; do
                mcopy -n -i "${IMAGE}@@${p1_off}" "::/${f}" "$EXTRACT_DIR/$f" 2>/dev/null \
                    || fail "Could not extract ${f} from the image boot partition"
            done
            KERNEL_FILE="$EXTRACT_DIR/vmlinuz"
            INITRD_FILE="$EXTRACT_DIR/initrd.img"
            ok "Extracted kernel + initrd to $EXTRACT_DIR"
        fi
    fi
fi

# Create UEFI vars file (writable copy). Skipped entirely in direct-kernel
# mode, where there is no firmware and $UEFI_CODE may legitimately be empty.
VARS_FILE="/tmp/${VM_NAME}-uefi-vars.fd"
if [[ "$BOOT_MODE" == "uefi" ]]; then
    [[ -z "$UEFI_CODE" ]] && fail "UEFI firmware not found. Install: apt install qemu-efi-aarch64 ovmf"
    if [[ ! -f "$VARS_FILE" ]] || [[ $(stat -c%s "$VARS_FILE") -ne $(stat -c%s "$UEFI_CODE") ]]; then
        if [[ -n "$UEFI_VARS_TEMPLATE" ]] && [[ -f "$UEFI_VARS_TEMPLATE" ]]; then
            cp "$UEFI_VARS_TEMPLATE" "$VARS_FILE"
            log "Using UEFI vars template: $UEFI_VARS_TEMPLATE"
        else
            # Create file matching firmware size
            truncate -s "$(stat -c%s "$UEFI_CODE")" "$VARS_FILE"
        fi
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

# Boot arguments, per the mode detected above.
if [[ "$BOOT_MODE" == "uefi" ]]; then
    QEMU_CMD+=(
        -drive "if=pflash,format=raw,file=$UEFI_CODE,readonly=on"
        -drive "if=pflash,format=raw,file=$VARS_FILE"
    )
else
    # The image is attached as virtio, so its second partition is /dev/vda2
    # here — not the mmcblk0p2 the Pi would see. `-machine virt` exposes a
    # PL011, hence ttyAMA0. No Pi DTB is passed: QEMU generates the device
    # tree for the virt machine, and a bcm2711 tree would not describe it.
    QEMU_CMD+=(
        -kernel "$KERNEL_FILE"
        -initrd "$INITRD_FILE"
        -append "root=/dev/vda2 rootfstype=ext4 rootwait console=ttyAMA0 loglevel=7"
    )
fi

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
