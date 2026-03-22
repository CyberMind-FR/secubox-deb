#!/bin/bash
# ══════════════════════════════════════════════════════════════════
#  SecuBox APT Repository Installer
#  Usage: curl -fsSL https://apt.secubox.in/install.sh | sudo bash
# ══════════════════════════════════════════════════════════════════
set -e

REPO_URL="https://apt.secubox.in"
KEYRING_PATH="/usr/share/keyrings/secubox.gpg"
SOURCES_PATH="/etc/apt/sources.list.d/secubox.list"
DIST="${DIST:-bookworm}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}[secubox]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
err()  { echo -e "${RED}[ERR]${NC} $*" >&2; exit 1; }

# Check root
[[ $EUID -ne 0 ]] && err "This script must be run as root (use sudo)"

# Check OS
if [[ ! -f /etc/debian_version ]]; then
  err "This script only supports Debian-based distributions"
fi

# Detect distribution
if [[ -f /etc/os-release ]]; then
  . /etc/os-release
  case "${VERSION_CODENAME}" in
    bookworm|bullseye|buster) DIST="${VERSION_CODENAME}" ;;
    trixie|sid) DIST="trixie" ;;
    *) log "Unknown distribution ${VERSION_CODENAME}, using ${DIST}" ;;
  esac
fi

log "Installing SecuBox APT repository..."
log "Distribution: ${DIST}"

# Install prerequisites
log "Installing prerequisites..."
apt-get update -qq
apt-get install -y -qq curl gnupg ca-certificates >/dev/null

# Download and install GPG key
log "Adding GPG key..."
curl -fsSL "${REPO_URL}/secubox-keyring.gpg" | tee "${KEYRING_PATH}" >/dev/null
chmod 644 "${KEYRING_PATH}"
ok "GPG key installed"

# Add repository
log "Adding repository..."
cat > "${SOURCES_PATH}" <<EOF
# SecuBox APT Repository
# https://github.com/gkerma/secubox-deb
deb [signed-by=${KEYRING_PATH}] ${REPO_URL} ${DIST} main
EOF
chmod 644 "${SOURCES_PATH}"
ok "Repository added"

# Update package lists
log "Updating package lists..."
apt-get update -qq

# Show available packages
log "Available SecuBox packages:"
echo ""
echo "  Metapackages (recommended):"
echo "    secubox-full   - Complete SecuBox installation (all 33 modules)"
echo "    secubox-lite   - Essential modules only (for ESPRESSObin)"
echo ""
echo "  Individual packages:"
echo "    secubox-core   - Core library (required by all)"
echo "    secubox-hub    - Central dashboard"
echo "    secubox-*      - Individual modules"
echo ""

ok "SecuBox repository installed successfully!"
echo ""
echo -e "${GREEN}════════════════════════════════════════════${NC}"
echo "  Install SecuBox:"
echo ""
echo "    sudo apt install secubox-full    # All modules"
echo "    sudo apt install secubox-lite    # Essential only"
echo ""
echo "  Web interface: https://localhost:8443"
echo -e "${GREEN}════════════════════════════════════════════${NC}"
