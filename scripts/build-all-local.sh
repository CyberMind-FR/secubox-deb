#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  build-all-local.sh — Build all SecuBox packages and add to local repo
#  Usage: bash scripts/build-all-local.sh [bookworm|trixie] [arm64|amd64]
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
PACKAGES_DIR="${REPO_DIR}/packages"
LOCAL_REPO="${REPO_DIR}/cache/repo"

SUITE="${1:-bookworm}"
ARCH="${2:-$(dpkg --print-architecture)}"

RED='\033[0;31m'; CYAN='\033[0;36m'; GOLD='\033[0;33m'
GREEN='\033[0;32m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${CYAN}[build]${NC} $*"; }
ok()   { echo -e "${GREEN}[  OK ]${NC} $*"; }
err()  { echo -e "${RED}[FAIL ]${NC} $*" >&2; }
warn() { echo -e "${GOLD}[ WARN]${NC} $*"; }

# Packages dans l'ordre de dépendance (core first, metapackages last)
PACKAGES=(
  # Core library (dependency for all)
  "secubox-core"
  # Dashboard & System
  "secubox-hub"
  "secubox-portal"
  "secubox-system"
  # Security
  "secubox-crowdsec"
  "secubox-wireguard"
  "secubox-auth"
  "secubox-nac"
  "secubox-waf"
  # Network
  "secubox-netmodes"
  "secubox-dpi"
  "secubox-qos"
  "secubox-vhost"
  "secubox-haproxy"
  "secubox-dns"
  # Monitoring
  "secubox-netdata"
  "secubox-mediaflow"
  "secubox-cdn"
  # Publishing
  "secubox-droplet"
  "secubox-streamlit"
  "secubox-streamforge"
  "secubox-metablogizer"
  "secubox-publish"
  # Email
  "secubox-mail"
  "secubox-mail-lxc"
  "secubox-webmail"
  "secubox-webmail-lxc"
  "secubox-users"
  # Metapackages (last)
  "secubox-full"
  "secubox-lite"
)

log "══════════════════════════════════════════════════════════"
log "Build all SecuBox packages for ${BOLD}${SUITE}/${ARCH}${NC}"
log "══════════════════════════════════════════════════════════"

# Vérifier que le repo local existe
if [[ ! -d "${LOCAL_REPO}/conf" ]]; then
  err "Repo local non initialisé. Exécuter d'abord :"
  err "  sudo bash scripts/setup-local-cache.sh"
  exit 1
fi

# Nettoyer les anciens .deb
cd "${PACKAGES_DIR}"
rm -f *.deb *.changes *.buildinfo 2>/dev/null || true

SUCCESS=0
FAILED=0

for PKG in "${PACKAGES[@]}"; do
  PKG_DIR="${PACKAGES_DIR}/${PKG}"

  if [[ ! -d "${PKG_DIR}/debian" ]]; then
    warn "SKIP ${PKG} — pas de debian/"
    continue
  fi

  log "Building ${BOLD}${PKG}${NC}..."

  cd "${PKG_DIR}"

  # Build le package
  BUILD_OK=0
  if [[ "$ARCH" == "arm64" ]] && [[ "$(uname -m)" != "aarch64" ]]; then
    # Cross-compile pour arm64
    if dpkg-buildpackage -a arm64 --host-arch arm64 -us -uc -b 2>/dev/null; then
      BUILD_OK=1
    fi
  else
    if dpkg-buildpackage -us -uc -b 2>/dev/null; then
      BUILD_OK=1
    fi
  fi

  if [[ $BUILD_OK -eq 1 ]]; then
    ok "${PKG} built"
    ((SUCCESS++))
  else
    err "${PKG} FAILED"
    ((FAILED++))
  fi
done

# Ajouter tous les .deb au repo local
cd "${PACKAGES_DIR}"
DEBS=$(ls -1 *.deb 2>/dev/null || true)

if [[ -n "$DEBS" ]]; then
  log "Adding packages to local repo..."
  for DEB in $DEBS; do
    if reprepro -b "${LOCAL_REPO}" includedeb "${SUITE}" "${DEB}" 2>/dev/null; then
      ok "Added ${DEB}"
    else
      warn "Failed to add ${DEB}"
    fi
  done
fi

# Résumé
echo ""
echo -e "${GOLD}${BOLD}════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  Build terminé !${NC}"
echo ""
echo -e "  Succès : ${SUCCESS}"
echo -e "  Échecs : ${FAILED}"
echo ""
echo -e "  Repo local : ${LOCAL_REPO}"
echo ""
echo -e "${CYAN}  Pour builder une image avec ces packages :${NC}"
echo -e "    sudo bash image/build-image.sh --board vm-x64 --local-cache"
echo -e "${GOLD}${BOLD}════════════════════════════════════════════════════════${NC}"
