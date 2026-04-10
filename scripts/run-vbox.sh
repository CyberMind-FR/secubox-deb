#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
# SecuBox — VirtualBox Launcher
# Create and launch SecuBox VM in VirtualBox with port forwarding
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Defaults
IMAGE="${PROJECT_DIR}/output/secubox-live-amd64-bookworm.img"
VM_NAME="SecuBox-Live"
RAM="4096"
CPUS="4"
SSH_PORT="2222"
HTTPS_PORT="9443"
HTTP_PORT="8080"
VRAM="128"

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] [IMAGE]

Create and launch SecuBox VM in VirtualBox.

Options:
    -n, --name NAME     VM name (default: SecuBox-Live)
    -m, --memory MB     RAM size (default: 4096)
    -c, --cpus N        Number of CPUs (default: 4)
    -s, --ssh PORT      Host SSH port (default: 2222)
    -w, --https PORT    Host HTTPS port (default: 9443)
    --delete            Delete existing VM first
    -h, --help          Show this help

Port Forwarding:
    SSH:    localhost:${SSH_PORT} → guest:22
    HTTPS:  localhost:${HTTPS_PORT} → guest:443
    HTTP:   localhost:${HTTP_PORT} → guest:80

Examples:
    $(basename "$0")                    # Create/start VM
    $(basename "$0") --delete           # Recreate VM from scratch
    $(basename "$0") -m 8192 -c 8       # More resources

EOF
    exit 0
}

DELETE_VM="no"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--name) VM_NAME="$2"; shift 2 ;;
        -m|--memory) RAM="$2"; shift 2 ;;
        -c|--cpus) CPUS="$2"; shift 2 ;;
        -s|--ssh) SSH_PORT="$2"; shift 2 ;;
        -w|--https) HTTPS_PORT="$2"; shift 2 ;;
        --delete) DELETE_VM="yes"; shift ;;
        -h|--help) usage ;;
        -*) echo "Unknown option: $1"; exit 1 ;;
        *) IMAGE="$1"; shift ;;
    esac
done

# Check VBoxManage
if ! command -v VBoxManage &>/dev/null; then
    echo "Error: VBoxManage not found. Install VirtualBox."
    exit 1
fi

# Validate image
if [[ ! -f "$IMAGE" ]]; then
    echo "Error: Image not found: $IMAGE"
    exit 1
fi

# Convert to VDI if needed
VDI_PATH="${IMAGE%.img}.vdi"
if [[ ! -f "$VDI_PATH" ]] || [[ "$IMAGE" -nt "$VDI_PATH" ]]; then
    echo "Converting image to VDI format..."
    VBoxManage convertfromraw "$IMAGE" "$VDI_PATH" --format VDI 2>/dev/null || {
        # If exists, delete and retry
        rm -f "$VDI_PATH"
        VBoxManage convertfromraw "$IMAGE" "$VDI_PATH" --format VDI
    }
fi

# Delete existing VM if requested
if [[ "$DELETE_VM" == "yes" ]]; then
    echo "Deleting existing VM: $VM_NAME"
    VBoxManage unregistervm "$VM_NAME" --delete 2>/dev/null || true
fi

# Check if VM exists
if VBoxManage showvminfo "$VM_NAME" &>/dev/null; then
    echo "VM '$VM_NAME' already exists. Starting..."
else
    echo "Creating VM: $VM_NAME"

    # Create VM
    VBoxManage createvm --name "$VM_NAME" --ostype "Debian_64" --register

    # Configure VM
    VBoxManage modifyvm "$VM_NAME" \
        --memory "$RAM" \
        --cpus "$CPUS" \
        --vram "$VRAM" \
        --graphicscontroller vmsvga \
        --firmware efi64 \
        --boot1 disk \
        --boot2 none \
        --nic1 nat \
        --nictype1 virtio \
        --audio-enabled off \
        --usb-ehci off \
        --usb-xhci on

    # Add storage controller
    VBoxManage storagectl "$VM_NAME" --name "SATA" --add sata --controller IntelAhci

    # Attach VDI
    VBoxManage storageattach "$VM_NAME" \
        --storagectl "SATA" \
        --port 0 \
        --device 0 \
        --type hdd \
        --medium "$VDI_PATH"

    # Port forwarding
    VBoxManage modifyvm "$VM_NAME" \
        --natpf1 "SSH,tcp,,${SSH_PORT},,22" \
        --natpf1 "HTTPS,tcp,,${HTTPS_PORT},,443" \
        --natpf1 "HTTP,tcp,,${HTTP_PORT},,80"

    echo "VM created successfully"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "SecuBox VirtualBox VM"
echo "═══════════════════════════════════════════════════════════════"
echo "VM Name: $VM_NAME"
echo "RAM:     ${RAM}MB"
echo "CPUs:    $CPUS"
echo ""
echo "Port Forwarding:"
echo "  SSH:   ssh -p $SSH_PORT root@localhost"
echo "  Web:   https://localhost:$HTTPS_PORT"
echo ""
echo "Default credentials: root / secubox"
echo "═══════════════════════════════════════════════════════════════"

# Start VM
echo "Starting VM..."
VBoxManage startvm "$VM_NAME" --type gui
