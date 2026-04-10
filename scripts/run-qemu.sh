#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
# SecuBox — QEMU Launcher
# Launch SecuBox Live image in QEMU with proper port forwarding
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Defaults
IMAGE="${PROJECT_DIR}/output/secubox-live-amd64-bookworm.img"
RAM="4096"
CPUS="4"
SSH_PORT="2222"
HTTPS_PORT="9443"
HTTP_PORT="8080"
DISPLAY_TYPE="gtk"
EFI="yes"

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] [IMAGE]

Launch SecuBox in QEMU with port forwarding.

Options:
    -m, --memory MB     RAM size (default: 4096)
    -c, --cpus N        Number of CPUs (default: 4)
    -s, --ssh PORT      Host SSH port (default: 2222)
    -w, --https PORT    Host HTTPS port (default: 9443)
    -d, --display TYPE  Display: gtk, sdl, none, vnc (default: gtk)
    --no-efi            Use BIOS instead of EFI
    -h, --help          Show this help

Port Forwarding:
    SSH:    localhost:${SSH_PORT} → guest:22
    HTTPS:  localhost:${HTTPS_PORT} → guest:443
    HTTP:   localhost:${HTTP_PORT} → guest:80

Examples:
    $(basename "$0")                    # Default settings
    $(basename "$0") -m 8192 -c 8       # More resources
    $(basename "$0") -d vnc             # VNC display on :5900
    $(basename "$0") /path/to/image.img # Custom image

EOF
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -m|--memory) RAM="$2"; shift 2 ;;
        -c|--cpus) CPUS="$2"; shift 2 ;;
        -s|--ssh) SSH_PORT="$2"; shift 2 ;;
        -w|--https) HTTPS_PORT="$2"; shift 2 ;;
        -d|--display) DISPLAY_TYPE="$2"; shift 2 ;;
        --no-efi) EFI="no"; shift ;;
        -h|--help) usage ;;
        -*) echo "Unknown option: $1"; exit 1 ;;
        *) IMAGE="$1"; shift ;;
    esac
done

# Validate image
if [[ ! -f "$IMAGE" ]]; then
    echo "Error: Image not found: $IMAGE"
    echo "Build with: sudo bash image/build-live-usb.sh"
    exit 1
fi

# Build QEMU command
QEMU_CMD=(
    qemu-system-x86_64
    -enable-kvm
    -m "$RAM"
    -cpu host
    -smp "$CPUS"
    -drive "file=$IMAGE,format=raw"
    -vga virtio
)

# EFI/BIOS
if [[ "$EFI" == "yes" ]]; then
    if [[ -f /usr/share/ovmf/OVMF.fd ]]; then
        QEMU_CMD+=(-bios /usr/share/ovmf/OVMF.fd)
    elif [[ -f /usr/share/OVMF/OVMF_CODE.fd ]]; then
        QEMU_CMD+=(-bios /usr/share/OVMF/OVMF_CODE.fd)
    else
        echo "Warning: OVMF not found, using BIOS"
    fi
fi

# Display
case "$DISPLAY_TYPE" in
    gtk) QEMU_CMD+=(-display gtk) ;;
    sdl) QEMU_CMD+=(-display sdl) ;;
    none) QEMU_CMD+=(-display none) ;;
    vnc) QEMU_CMD+=(-display vnc=:0) ;;
    *) echo "Unknown display: $DISPLAY_TYPE"; exit 1 ;;
esac

# Network with port forwarding
QEMU_CMD+=(
    -netdev "user,id=net0,hostfwd=tcp::${SSH_PORT}-:22,hostfwd=tcp::${HTTPS_PORT}-:443,hostfwd=tcp::${HTTP_PORT}-:80"
    -device virtio-net-pci,netdev=net0
)

echo "═══════════════════════════════════════════════════════════════"
echo "SecuBox QEMU Launcher"
echo "═══════════════════════════════════════════════════════════════"
echo "Image:   $IMAGE"
echo "RAM:     ${RAM}MB"
echo "CPUs:    $CPUS"
echo "Display: $DISPLAY_TYPE"
echo ""
echo "Port Forwarding:"
echo "  SSH:   ssh -p $SSH_PORT root@localhost"
echo "  Web:   https://localhost:$HTTPS_PORT"
echo ""
echo "Default credentials: root / secubox"
echo "═══════════════════════════════════════════════════════════════"

exec "${QEMU_CMD[@]}"
