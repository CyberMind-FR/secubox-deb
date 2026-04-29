#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  SecuBox VirtualBox Setup Script
#  Downloads and configures SecuBox VM for VirtualBox
#  Usage: bash vbox-setup.sh [OPTIONS]
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

VERSION="1.0.0"
VM_NAME="SecuBox"
VM_MEMORY=2048
VM_CPUS=2
VM_VRAM=64
GITHUB_REPO="CyberMind-FR/secubox-deb"
VDI_FILE=""
DOWNLOAD_URL=""
NETWORK_MODE="bridged"
BRIDGE_ADAPTER=""
FORCE=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
GOLD='\033[0;33m'
NC='\033[0m'
BOLD='\033[1m'

log()  { echo -e "${CYAN}[secubox]${NC} $*"; }
ok()   { echo -e "${GREEN}[  OK  ]${NC} $*"; }
err()  { echo -e "${RED}[ERROR ]${NC} $*" >&2; exit 1; }
warn() { echo -e "${GOLD}[ WARN ]${NC} $*"; }

usage() {
    cat <<EOF
${BOLD}SecuBox VirtualBox Setup${NC} v${VERSION}

Usage: $0 [OPTIONS]

Options:
  --vdi FILE          Use existing VDI file instead of downloading
  --name NAME         VM name (default: SecuBox)
  --memory MB         RAM in MB (default: 2048)
  --cpus N            CPU count (default: 2)
  --network MODE      bridged|nat|hostonly (default: bridged)
  --bridge ADAPTER    Bridge adapter name (auto-detected if omitted)
  --force             Overwrite existing VM
  --version TAG       Download specific version (default: latest)
  --help              Show this help

Examples:
  $0                              # Download latest and setup
  $0 --vdi secubox.vdi            # Use existing VDI
  $0 --network nat --memory 4096  # NAT mode, 4GB RAM
  $0 --version v1.5.0             # Specific version

EOF
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --vdi)       VDI_FILE="$2"; shift 2 ;;
        --name)      VM_NAME="$2"; shift 2 ;;
        --memory)    VM_MEMORY="$2"; shift 2 ;;
        --cpus)      VM_CPUS="$2"; shift 2 ;;
        --network)   NETWORK_MODE="$2"; shift 2 ;;
        --bridge)    BRIDGE_ADAPTER="$2"; shift 2 ;;
        --force)     FORCE=1; shift ;;
        --version)   VERSION_TAG="$2"; shift 2 ;;
        --help|-h)   usage ;;
        *)           err "Unknown option: $1" ;;
    esac
done

# Check VirtualBox
command -v VBoxManage >/dev/null 2>&1 || err "VirtualBox not found. Install it first."

log "SecuBox VirtualBox Setup v${VERSION}"
echo ""

# Check if VM exists
if VBoxManage showvminfo "$VM_NAME" &>/dev/null; then
    if [[ $FORCE -eq 1 ]]; then
        warn "VM '$VM_NAME' exists, removing..."
        VBoxManage controlvm "$VM_NAME" poweroff 2>/dev/null || true
        sleep 2
        VBoxManage unregistervm "$VM_NAME" --delete 2>/dev/null || true
    else
        err "VM '$VM_NAME' already exists. Use --force to overwrite or --name for different name."
    fi
fi

# Download VDI if not provided
if [[ -z "$VDI_FILE" ]]; then
    log "Fetching latest release from GitHub..."

    if [[ -n "${VERSION_TAG:-}" ]]; then
        RELEASE_URL="https://api.github.com/repos/${GITHUB_REPO}/releases/tags/${VERSION_TAG}"
    else
        RELEASE_URL="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
    fi

    # Get download URL
    DOWNLOAD_URL=$(curl -fsSL "$RELEASE_URL" 2>/dev/null | \
        grep -oP '"browser_download_url":\s*"\K[^"]*vm-x64[^"]*\.vdi\.gz' | head -1)

    if [[ -z "$DOWNLOAD_URL" ]]; then
        # Try .img.gz if .vdi.gz not found
        DOWNLOAD_URL=$(curl -fsSL "$RELEASE_URL" 2>/dev/null | \
            grep -oP '"browser_download_url":\s*"\K[^"]*vm-x64[^"]*\.img\.gz' | head -1)

        if [[ -z "$DOWNLOAD_URL" ]]; then
            err "Could not find SecuBox VM image in releases. Check $RELEASE_URL"
        fi
    fi

    VDI_FILE="secubox-vm-x64.vdi"
    DOWNLOAD_FILE=$(basename "$DOWNLOAD_URL")

    log "Downloading: $DOWNLOAD_URL"
    curl -fSL --progress-bar -o "$DOWNLOAD_FILE" "$DOWNLOAD_URL"

    log "Decompressing..."
    if [[ "$DOWNLOAD_FILE" == *.vdi.gz ]]; then
        gunzip -c "$DOWNLOAD_FILE" > "$VDI_FILE"
    elif [[ "$DOWNLOAD_FILE" == *.img.gz ]]; then
        gunzip -c "$DOWNLOAD_FILE" > "secubox-vm-x64.img"
        log "Converting IMG to VDI..."
        qemu-img convert -f raw -O vdi "secubox-vm-x64.img" "$VDI_FILE"
        rm -f "secubox-vm-x64.img"
    fi

    rm -f "$DOWNLOAD_FILE"
    ok "Downloaded: $VDI_FILE"
else
    [[ -f "$VDI_FILE" ]] || err "VDI file not found: $VDI_FILE"
    log "Using existing VDI: $VDI_FILE"
fi

# Get absolute path
VDI_PATH="$(cd "$(dirname "$VDI_FILE")" && pwd)/$(basename "$VDI_FILE")"

# Auto-detect bridge adapter
if [[ "$NETWORK_MODE" == "bridged" && -z "$BRIDGE_ADAPTER" ]]; then
    BRIDGE_ADAPTER=$(ip -o link show | awk -F': ' '/state UP/ && !/lo|docker|veth|br-|virbr/ {print $2; exit}')
    if [[ -z "$BRIDGE_ADAPTER" ]]; then
        warn "Could not detect network adapter, using NAT mode"
        NETWORK_MODE="nat"
    else
        log "Detected network adapter: $BRIDGE_ADAPTER"
    fi
fi

# Create VM
log "Creating VM: $VM_NAME"

VBoxManage createvm --name "$VM_NAME" --ostype Debian_64 --register

# Configure VM
log "Configuring VM..."
VBoxManage modifyvm "$VM_NAME" \
    --memory "$VM_MEMORY" \
    --cpus "$VM_CPUS" \
    --firmware efi \
    --graphicscontroller vmsvga \
    --vram "$VM_VRAM" \
    --audio-driver pulse \
    --boot1 disk \
    --boot2 none \
    --boot3 none \
    --boot4 none \
    --rtcuseutc on \
    --ioapic on

# Network configuration
case "$NETWORK_MODE" in
    bridged)
        VBoxManage modifyvm "$VM_NAME" --nic1 bridged --bridgeadapter1 "$BRIDGE_ADAPTER"
        log "Network: Bridged to $BRIDGE_ADAPTER"
        ;;
    nat)
        VBoxManage modifyvm "$VM_NAME" --nic1 nat
        VBoxManage modifyvm "$VM_NAME" --natpf1 "https,tcp,,9443,,9443"
        VBoxManage modifyvm "$VM_NAME" --natpf1 "ssh,tcp,,2222,,22"
        log "Network: NAT with port forwarding (9443→9443, 2222→22)"
        ;;
    hostonly)
        # Create host-only network if needed
        VBoxManage hostonlyif create 2>/dev/null || true
        HOSTONLY_IF=$(VBoxManage list hostonlyifs | grep -m1 "^Name:" | awk '{print $2}')
        VBoxManage modifyvm "$VM_NAME" --nic1 hostonly --hostonlyadapter1 "$HOSTONLY_IF"
        log "Network: Host-only ($HOSTONLY_IF)"
        ;;
    *)
        err "Unknown network mode: $NETWORK_MODE"
        ;;
esac

# Add storage controller
VBoxManage storagectl "$VM_NAME" --name "SATA" --add sata --bootable on

# Attach VDI
log "Attaching disk: $VDI_PATH"
VBoxManage storageattach "$VM_NAME" \
    --storagectl "SATA" \
    --port 0 \
    --device 0 \
    --type hdd \
    --medium "$VDI_PATH"

ok "VM created successfully!"

echo ""
echo -e "${BOLD}════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  SecuBox VM Ready!${NC}"
echo ""
echo -e "  ${CYAN}VM Name:${NC}     $VM_NAME"
echo -e "  ${CYAN}Memory:${NC}      ${VM_MEMORY}MB"
echo -e "  ${CYAN}CPUs:${NC}        $VM_CPUS"
echo -e "  ${CYAN}Network:${NC}     $NETWORK_MODE"
echo -e "  ${CYAN}Disk:${NC}        $VDI_PATH"
echo ""
echo -e "  ${GOLD}Credentials:${NC} root / secubox"
echo ""
if [[ "$NETWORK_MODE" == "nat" ]]; then
    echo -e "  ${CYAN}WebUI:${NC}       https://localhost:9443"
    echo -e "  ${CYAN}SSH:${NC}         ssh -p 2222 root@localhost"
else
    echo -e "  ${CYAN}WebUI:${NC}       https://<VM-IP>:9443"
fi
echo ""
echo -e "${BOLD}════════════════════════════════════════════${NC}"
echo ""

# Offer to start
read -p "Start VM now? [Y/n] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    log "Starting VM..."
    VBoxManage startvm "$VM_NAME" --type gui
    ok "VM started!"
    echo ""
    echo "Boot modes (GRUB menu):"
    echo "  1. SecuBox (Kiosk Mode)    ← Default"
    echo "  2. SecuBox (Console Mode)"
    echo "  3. SecuBox (Recovery)"
    echo ""
    echo "Console access: Ctrl+Alt+F2"
fi
