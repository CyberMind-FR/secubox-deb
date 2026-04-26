#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# SecuBox Eye Remote :: slipstream-remote.sh
# CyberMind — Gérald Kerma
#
# Slipstream SecuBox packages into storage.img via SSH
# Either runs locally with image pulled from Pi, or directly on Pi
#
# Usage: ./slipstream-remote.sh [user@host] [--pull|--on-device]
#   --pull       Pull image locally, slipstream, push back (default)
#   --on-device  Copy packages to Pi and run slipstream there
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DEBS_DIR="${REPO_DIR}/output/debs"

RED='\033[0;31m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'
GOLD='\033[0;33m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${CYAN}[slipstream]${NC} $*"; }
ok()   { echo -e "${GREEN}[    OK    ]${NC} $*"; }
err()  { echo -e "${RED}[   FAIL   ]${NC} $*" >&2; exit 1; }
warn() { echo -e "${GOLD}[   WARN   ]${NC} $*"; }

# Defaults
HOST=""
MODE="pull"  # pull or on-device
STORAGE_PATH="/var/lib/secubox/eye-remote/storage.img"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --pull)       MODE="pull"; shift ;;
        --on-device)  MODE="on-device"; shift ;;
        --help|-h)
            echo "Usage: $0 [user@host] [--pull|--on-device]"
            echo ""
            echo "Options:"
            echo "  --pull       Pull image locally, slipstream, push back (default)"
            echo "  --on-device  Copy packages to Pi and slipstream there"
            exit 0
            ;;
        *)
            if [[ "$1" == *@* ]]; then
                HOST="$1"
            fi
            shift
            ;;
    esac
done

# Find Pi if not specified
find_pi() {
    local hosts=(
        "pi@10.55.0.2"
        "pi@raspberrypi.local"
        "pi@secubox-eye.local"
    )
    for h in "${hosts[@]}"; do
        if ssh -o ConnectTimeout=3 -o BatchMode=yes "$h" 'exit 0' 2>/dev/null; then
            HOST="$h"
            ok "Found Pi at $h"
            return 0
        fi
    done
    return 1
}

if [[ -z "$HOST" ]]; then
    log "Scanning for Pi..."
    find_pi || err "Could not find Pi. Specify: $0 pi@hostname"
fi

log "═══════════════════════════════════════════════════════════════"
log " SecuBox Eye Remote - Remote Slipstream"
log "═══════════════════════════════════════════════════════════════"
log "Target: $HOST"
log "Mode:   $MODE"
log "Packages: ${DEBS_DIR}"
echo ""

# Count packages
DEB_COUNT=$(find "$DEBS_DIR" -maxdepth 1 -name "secubox-*.deb" 2>/dev/null | wc -l)
log "Found ${DEB_COUNT} SecuBox packages"

if [[ $DEB_COUNT -eq 0 ]]; then
    err "No secubox-*.deb packages found in $DEBS_DIR"
fi

# Check storage image exists on Pi
log "Checking storage image on Pi..."
if ! ssh "$HOST" "[[ -f '$STORAGE_PATH' ]]"; then
    err "Storage image not found on Pi at $STORAGE_PATH"
fi
REMOTE_SIZE=$(ssh "$HOST" "ls -lh '$STORAGE_PATH' | awk '{print \$5}'")
log "Remote storage.img: $REMOTE_SIZE"

if [[ "$MODE" == "on-device" ]]; then
    # ══════════════════════════════════════════════════════════════════════
    # Mode: Run slipstream directly on the Pi
    # ══════════════════════════════════════════════════════════════════════
    log "Mode: on-device slipstream"

    # Check if qemu-user-static is available (for arm64 chroot)
    log "Checking QEMU on Pi..."
    HAS_QEMU=$(ssh "$HOST" "[[ -f /usr/bin/qemu-aarch64-static ]] && echo yes || echo no")
    if [[ "$HAS_QEMU" == "no" ]]; then
        warn "QEMU not found on Pi - installing..."
        ssh "$HOST" "sudo apt-get update -qq && sudo apt-get install -y qemu-user-static" || true
    fi

    # Create temp directory on Pi
    log "Copying packages to Pi..."
    ssh "$HOST" "mkdir -p /tmp/secubox-debs"

    # Copy packages in batches to avoid overwhelming
    BATCH_SIZE=20
    DEBS=("$DEBS_DIR"/secubox-*.deb)
    TOTAL=${#DEBS[@]}

    for ((i=0; i<TOTAL; i+=BATCH_SIZE)); do
        BATCH=("${DEBS[@]:i:BATCH_SIZE}")
        log "Copying batch $((i/BATCH_SIZE + 1))... ($(( i + ${#BATCH[@]} ))/$TOTAL)"
        scp "${BATCH[@]}" "$HOST:/tmp/secubox-debs/" 2>/dev/null
    done
    ok "Copied $TOTAL packages"

    # Copy slipstream script
    log "Copying slipstream script..."
    scp "${SCRIPT_DIR}/slipstream-storage.sh" "$HOST:/tmp/"
    ssh "$HOST" "chmod +x /tmp/slipstream-storage.sh"

    # Run slipstream
    log "Running slipstream on Pi (this may take a while)..."
    ssh -t "$HOST" "sudo /tmp/slipstream-storage.sh --image '$STORAGE_PATH' --debs /tmp/secubox-debs"

    # Cleanup
    ssh "$HOST" "rm -rf /tmp/secubox-debs /tmp/slipstream-storage.sh"

else
    # ══════════════════════════════════════════════════════════════════════
    # Mode: Pull image, slipstream locally, push back
    # ══════════════════════════════════════════════════════════════════════
    log "Mode: pull/push slipstream"

    WORK_DIR=$(mktemp -d /tmp/slipstream-XXXXXX)
    LOCAL_IMG="${WORK_DIR}/storage.img"

    cleanup() {
        log "Cleaning up..."
        rm -rf "$WORK_DIR"
    }
    trap cleanup EXIT

    # Stop gadget service to release the image
    log "Stopping gadget service on Pi..."
    ssh "$HOST" "sudo systemctl stop secubox-eye-gadget 2>/dev/null || true"
    sleep 2

    # Pull image
    log "Pulling storage.img from Pi (this may take a while)..."
    scp "$HOST:$STORAGE_PATH" "$LOCAL_IMG"
    LOCAL_SIZE=$(ls -lh "$LOCAL_IMG" | awk '{print $5}')
    ok "Downloaded: $LOCAL_SIZE"

    # Run local slipstream
    log "Running local slipstream..."
    sudo bash "${SCRIPT_DIR}/slipstream-storage.sh" --image "$LOCAL_IMG" --debs "$DEBS_DIR"

    # Push image back
    log "Pushing updated storage.img back to Pi..."
    scp "$LOCAL_IMG" "$HOST:/tmp/storage.img.new"
    ssh "$HOST" "sudo mv /tmp/storage.img.new '$STORAGE_PATH'"
    ok "Image pushed back"

    # Restart gadget service
    log "Restarting gadget service on Pi..."
    ssh "$HOST" "sudo systemctl start secubox-eye-gadget"
fi

echo ""
log "═══════════════════════════════════════════════════════════════"
echo -e "${GREEN}${BOLD}Slipstream complete!${NC}"
echo ""
echo "  The USB storage now contains SecuBox modules."
echo ""
echo "  To boot the ESPRESSObin with updated image:"
echo "  1. Connect Pi Zero to ESPRESSObin USB"
echo "  2. In U-Boot: usb start && usb reset && run bootcmd_usb0"
echo ""
echo "  The booted system should now have SecuBox packages installed."
log "═══════════════════════════════════════════════════════════════"
