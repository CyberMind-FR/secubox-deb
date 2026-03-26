#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  SecuBox-DEB — build-c3box-clone.sh
#  Build a complete clone image of the current C3Box device
#  Usage: sudo bash image/build-c3box-clone.sh [OPTIONS]
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

# ── Defaults ──────────────────────────────────────────────────────
C3BOX_HOST="${C3BOX_HOST:-localhost}"
C3BOX_PORT="${C3BOX_PORT:-2222}"
C3BOX_USER="${C3BOX_USER:-root}"
OUT_DIR="${REPO_DIR}/output"
SUITE="bookworm"
USE_LOCAL_CACHE=0
SLIPSTREAM_DEBS=1
SSH_KEY=""
SKIP_EXPORT=0

RED='\033[0;31m'; CYAN='\033[0;36m'; GOLD='\033[0;33m'
GREEN='\033[0;32m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${CYAN}[c3box-clone]${NC} $*"; }
ok()   { echo -e "${GREEN}[    OK    ]${NC} $*"; }
err()  { echo -e "${RED}[   FAIL   ]${NC} $*" >&2; exit 1; }
warn() { echo -e "${GOLD}[   WARN   ]${NC} $*"; }

# ── Parse args ────────────────────────────────────────────────────
usage() {
  cat <<EOF
Usage: sudo bash build-c3box-clone.sh [OPTIONS]

Connection Options:
  --host HOST      C3Box host (default: localhost, or \$C3BOX_HOST)
  --port PORT      SSH port (default: 2222, or \$C3BOX_PORT)
  --user USER      SSH user (default: root, or \$C3BOX_USER)
  --key  FILE      SSH private key file

Build Options:
  --out DIR        Output directory (default: ./output)
  --suite SUITE    Debian suite (default: bookworm)
  --local-cache    Use local APT cache
  --slipstream     Include .deb packages from output/debs/ (default: enabled)
  --no-slipstream  Don't include local packages
  --skip-export    Use existing preseed (don't re-export from device)
  --help           Show this help

This script:
  1. Exports the current C3Box device configuration
  2. Builds a bootable installer/live ISO with the configuration
  3. The ISO can boot live OR install headlessly to any x64 PC

Examples:
  # Clone from VM on port 2222
  sudo bash build-c3box-clone.sh --host localhost --port 2222

  # Clone from remote device
  sudo bash build-c3box-clone.sh --host 192.168.1.100 --port 22

  # Use existing export, rebuild ISO only
  sudo bash build-c3box-clone.sh --skip-export

Output:
  secubox-c3box-clone-amd64-bookworm.iso   - Bootable ISO
  secubox-c3box-clone-amd64-bookworm.img   - USB image
  c3box-clone-preseed.tar.gz               - Configuration archive

EOF
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)         C3BOX_HOST="$2";     shift 2 ;;
    --port)         C3BOX_PORT="$2";     shift 2 ;;
    --user)         C3BOX_USER="$2";     shift 2 ;;
    --key)          SSH_KEY="$2";        shift 2 ;;
    --out)          OUT_DIR="$2";        shift 2 ;;
    --suite)        SUITE="$2";          shift 2 ;;
    --local-cache)  USE_LOCAL_CACHE=1;   shift   ;;
    --slipstream)   SLIPSTREAM_DEBS=1;   shift   ;;
    --no-slipstream) SLIPSTREAM_DEBS=0;  shift   ;;
    --skip-export)  SKIP_EXPORT=1;       shift   ;;
    --help|-h)      usage ;;
    *) err "Unknown argument: $1" ;;
  esac
done

# ── Checks ────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && err "This script must be run as root (sudo)"

mkdir -p "$OUT_DIR"
PRESEED_FILE="${OUT_DIR}/c3box-clone-preseed.tar.gz"
ISO_FILE="${OUT_DIR}/secubox-c3box-clone-amd64-${SUITE}.iso"

echo ""
echo -e "${GOLD}${BOLD}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}        C3Box Clone Builder${NC}"
echo -e "${GOLD}${BOLD}════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Source Device: ${C3BOX_USER}@${C3BOX_HOST}:${C3BOX_PORT}"
echo -e "  Output:        ${ISO_FILE}"
echo ""

# ── Step 1: Export configuration ──────────────────────────────────
if [[ $SKIP_EXPORT -eq 0 ]]; then
  log "════════════════════════════════════════════════════════════"
  log "Phase 1: Exporting C3Box Configuration"
  log "════════════════════════════════════════════════════════════"

  EXPORT_OPTS="--host $C3BOX_HOST --port $C3BOX_PORT --user $C3BOX_USER --out $OUT_DIR"
  [ -n "$SSH_KEY" ] && EXPORT_OPTS+=" --key $SSH_KEY"

  if ! bash "${SCRIPT_DIR}/export-c3box-clone.sh" $EXPORT_OPTS; then
    err "Failed to export C3Box configuration"
  fi

  ok "Configuration exported"
else
  if [[ ! -f "$PRESEED_FILE" ]]; then
    err "No preseed file found at ${PRESEED_FILE}. Cannot skip export."
  fi
  log "Skipping export, using existing preseed: ${PRESEED_FILE}"
fi

# ── Step 2: Build ISO ─────────────────────────────────────────────
log "════════════════════════════════════════════════════════════"
log "Phase 2: Building Clone ISO"
log "════════════════════════════════════════════════════════════"

BUILD_OPTS="--suite $SUITE --out $OUT_DIR --name secubox-c3box-clone --preseed $PRESEED_FILE"
[[ $USE_LOCAL_CACHE -eq 1 ]] && BUILD_OPTS+=" --local-cache"
[[ $SLIPSTREAM_DEBS -eq 1 ]] && BUILD_OPTS+=" --slipstream"

if ! bash "${SCRIPT_DIR}/build-installer-iso.sh" $BUILD_OPTS; then
  err "Failed to build ISO"
fi

# ── Complete ──────────────────────────────────────────────────────
IMG_FILE="${OUT_DIR}/secubox-c3box-clone-amd64-${SUITE}.img"
ISO_SIZE=$(du -sh "$ISO_FILE" 2>/dev/null | cut -f1 || echo "N/A")
IMG_SIZE=$(du -sh "$IMG_FILE" 2>/dev/null | cut -f1 || echo "N/A")

echo ""
echo -e "${GOLD}${BOLD}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}        C3Box Clone Image Ready!${NC}"
echo -e "${GOLD}${BOLD}════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}Output Files:${NC}"
echo -e "    ISO:     ${ISO_FILE} (${ISO_SIZE})"
echo -e "    IMG:     ${IMG_FILE} (${IMG_SIZE})"
echo -e "    Preseed: ${PRESEED_FILE}"
echo ""
echo -e "  ${BOLD}Write to USB Drive:${NC}"
echo -e "    sudo dd if=${IMG_FILE} of=/dev/sdX bs=4M status=progress"
echo ""
echo -e "  ${BOLD}Boot Options:${NC}"
echo -e "    1. SecuBox Live       - Boot live, test before installing"
echo -e "    2. SecuBox Install    - Headless auto-install to disk"
echo ""
echo -e "  ${BOLD}After Installation:${NC}"
echo -e "    - All settings will be restored from your C3Box"
echo -e "    - Same users, passwords, SSH keys"
echo -e "    - Same network configuration"
echo -e "    - Same services and SSL certificates"
echo ""
echo -e "  ${BOLD}Default Credentials (if not changed):${NC}"
echo -e "    SSH:    root / secubox"
echo -e "    Web UI: admin / admin"
echo ""
echo -e "${GOLD}${BOLD}════════════════════════════════════════════════════════════${NC}"
