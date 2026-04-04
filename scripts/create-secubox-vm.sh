#!/bin/bash
# SecuBox VirtualBox VM Creator
# CyberMind — https://cybermind.fr
#
# Usage:
#   ./create-secubox-vm.sh <image.vdi>
#   ./create-secubox-vm.sh <image.img>    # Auto-converts to VDI
#   ./create-secubox-vm.sh --download     # Downloads latest and creates VM
#
# Examples:
#   ./create-secubox-vm.sh secubox-live.vdi
#   ./create-secubox-vm.sh --download
#   ./create-secubox-vm.sh secubox-live.img --name "SecuBox-Test"

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Defaults
VM_NAME="SecuBox-Live"
MEMORY=4096
CPUS=2
VRAM=128
SSH_PORT=2222
HTTPS_PORT=9443
FIRMWARE="efi"
DOWNLOAD_URL="https://github.com/CyberMind-FR/secubox-deb/releases/latest/download/secubox-live-amd64-bookworm.img.gz"

usage() {
    cat << EOF
SecuBox VirtualBox VM Creator

Usage: $0 [OPTIONS] <image.vdi|image.img|--download>

Options:
    --name NAME       VM name (default: SecuBox-Live)
    --memory MB       RAM in MB (default: 4096)
    --cpus N          CPU count (default: 2)
    --ssh-port PORT   SSH forward port (default: 2222)
    --https-port PORT HTTPS forward port (default: 9443)
    --headless        Start in headless mode
    --no-start        Create VM but don't start
    --download        Download latest image first
    -h, --help        Show this help

Examples:
    $0 secubox-live.vdi
    $0 secubox-live.img --name "SecuBox-Dev"
    $0 --download --headless
    $0 --download --ssh-port 2223 --https-port 9444

EOF
    exit 0
}

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[!]${NC} $1"; exit 1; }
info() { echo -e "${CYAN}[i]${NC} $1"; }

# Parse arguments
IMAGE=""
HEADLESS=false
NO_START=false
DOWNLOAD=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --name) VM_NAME="$2"; shift 2 ;;
        --memory) MEMORY="$2"; shift 2 ;;
        --cpus) CPUS="$2"; shift 2 ;;
        --ssh-port) SSH_PORT="$2"; shift 2 ;;
        --https-port) HTTPS_PORT="$2"; shift 2 ;;
        --headless) HEADLESS=true; shift ;;
        --no-start) NO_START=true; shift ;;
        --download) DOWNLOAD=true; shift ;;
        -h|--help) usage ;;
        -*) error "Unknown option: $1" ;;
        *) IMAGE="$1"; shift ;;
    esac
done

# Check VirtualBox
command -v VBoxManage &>/dev/null || error "VirtualBox not installed"

# Download if requested
if $DOWNLOAD; then
    log "Downloading SecuBox Live image..."
    if command -v wget &>/dev/null; then
        wget -q --show-progress -O secubox-live.img.gz "$DOWNLOAD_URL"
    elif command -v curl &>/dev/null; then
        curl -L -o secubox-live.img.gz "$DOWNLOAD_URL"
    else
        error "wget or curl required for download"
    fi
    log "Extracting..."
    gunzip -f secubox-live.img.gz
    IMAGE="secubox-live.img"
fi

# Validate image
[[ -n "$IMAGE" ]] || error "No image specified. Use --download or provide image path."
[[ -f "$IMAGE" ]] || error "Image not found: $IMAGE"

# Convert IMG to VDI if needed
if [[ "$IMAGE" == *.img ]]; then
    VDI="${IMAGE%.img}.vdi"
    if [[ ! -f "$VDI" ]]; then
        log "Converting IMG to VDI..."
        VBoxManage convertfromraw "$IMAGE" "$VDI" --format VDI
    else
        info "Using existing VDI: $VDI"
    fi
    IMAGE="$VDI"
fi

# Get absolute path
IMAGE="$(realpath "$IMAGE")"

# Check if VM exists
if VBoxManage showvminfo "$VM_NAME" &>/dev/null; then
    warn "VM '$VM_NAME' already exists"
    read -p "Delete and recreate? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        VBoxManage controlvm "$VM_NAME" poweroff 2>/dev/null || true
        sleep 1
        VBoxManage unregistervm "$VM_NAME" --delete 2>/dev/null || true
    else
        error "Aborted"
    fi
fi

# Create VM
log "Creating VM: $VM_NAME"
VBoxManage createvm --name "$VM_NAME" --ostype "Debian_64" --register

# Configure VM
log "Configuring VM (${MEMORY}MB RAM, ${CPUS} CPUs)..."
VBoxManage modifyvm "$VM_NAME" \
    --memory "$MEMORY" \
    --cpus "$CPUS" \
    --vram "$VRAM" \
    --graphicscontroller vboxsvga \
    --firmware "$FIRMWARE" \
    --boot1 disk \
    --boot2 none \
    --nic1 nat \
    --natpf1 "SSH,tcp,,$SSH_PORT,,22" \
    --natpf1 "HTTPS,tcp,,$HTTPS_PORT,,443" \
    --clipboard bidirectional \
    --draganddrop bidirectional \
    --usb on \
    --audio-enabled off

# Add storage controller
log "Attaching disk..."
VBoxManage storagectl "$VM_NAME" --name "SATA" --add sata --controller IntelAhci
VBoxManage storageattach "$VM_NAME" --storagectl "SATA" --port 0 --device 0 \
    --type hdd --medium "$IMAGE"

# Show summary
echo ""
echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  SecuBox VM Created Successfully${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  VM Name:    ${CYAN}$VM_NAME${NC}"
echo -e "  Memory:     ${MEMORY}MB"
echo -e "  CPUs:       $CPUS"
echo -e "  Disk:       $IMAGE"
echo ""
echo -e "  ${YELLOW}Access (after boot):${NC}"
echo -e "  SSH:        ssh -p $SSH_PORT root@localhost"
echo -e "  Web UI:     https://localhost:$HTTPS_PORT"
echo -e "  Password:   ${CYAN}secubox${NC}"
echo ""

# Start VM
if ! $NO_START; then
    log "Starting VM..."
    if $HEADLESS; then
        VBoxManage startvm "$VM_NAME" --type headless
        info "VM running in headless mode"
        info "Use 'VBoxManage controlvm $VM_NAME poweroff' to stop"
    else
        VBoxManage startvm "$VM_NAME" --type gui
    fi
    echo ""
    info "Wait 30-60 seconds for boot to complete"
else
    info "VM created but not started (--no-start)"
    info "Start with: VBoxManage startvm \"$VM_NAME\""
fi
