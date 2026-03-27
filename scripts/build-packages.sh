#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  build-packages.sh — Build all SecuBox .deb packages
#  Usage: bash scripts/build-packages.sh [bookworm|trixie] [arm64|amd64]
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
PACKAGES_DIR="${REPO_DIR}/packages"
OUTPUT_DIR="${REPO_DIR}/output/debs"

SUITE="${1:-bookworm}"
ARCH="${2:-$(dpkg --print-architecture)}"

RED='\033[0;31m'; CYAN='\033[0;36m'; GOLD='\033[0;33m'
GREEN='\033[0;32m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${CYAN}[build]${NC} $*"; }
ok()   { echo -e "${GREEN}[  OK ]${NC} $*"; }
err()  { echo -e "${RED}[FAIL ]${NC} $*" >&2; }
warn() { echo -e "${GOLD}[ WARN]${NC} $*"; }

# Packages dans l'ordre de dépendance
PACKAGES=(
  "secubox-core"
  "secubox-hub"
  "secubox-crowdsec"
  "secubox-netdata"
  "secubox-wireguard"
  "secubox-vhost"
  "secubox-dpi"
  "secubox-ndpid"
  "secubox-mediaflow"
  "secubox-qos"
  "secubox-system"
  "secubox-system-hub"
  "secubox-netmodes"
  "secubox-nac"
  "secubox-auth"
  "secubox-cdn"
  "secubox-ai-gateway"
  "secubox-localrecall"
  "secubox-master-link"
  "secubox-threat-analyst"
  "secubox-cve-triage"
  "secubox-network-anomaly"
  "secubox-dns-guard"
  "secubox-iot-guard"
  "secubox-config-advisor"
  "secubox-mcp-server"
  "secubox-identity"
  "secubox-ad-guard"
  "secubox-full"
  "secubox-lite"
)

log "══════════════════════════════════════════════════════════"
log "Build all SecuBox packages for ${BOLD}${SUITE}/${ARCH}${NC}"
log "══════════════════════════════════════════════════════════"

# Vérifier build deps
MISSING_DEPS=""
command -v dpkg-buildpackage >/dev/null || MISSING_DEPS+=" dpkg-dev"
dpkg -l debhelper >/dev/null 2>&1 || MISSING_DEPS+=" debhelper"
dpkg -l dh-python >/dev/null 2>&1 || MISSING_DEPS+=" dh-python"
dpkg -l python3-all >/dev/null 2>&1 || MISSING_DEPS+=" python3-all"

if [[ -n "$MISSING_DEPS" ]]; then
  err "Missing build dependencies:$MISSING_DEPS"
  echo ""
  echo "Install with:"
  echo "  sudo apt install$MISSING_DEPS"
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"

# Nettoyer les anciens .deb dans packages/
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

  # Rendre rules exécutable
  chmod +x debian/rules 2>/dev/null || true

  # Build le package
  BUILD_OK=0
  if [[ "$ARCH" == "arm64" ]] && [[ "$(uname -m)" != "aarch64" ]]; then
    # Cross-compile pour arm64
    if dpkg-buildpackage -a arm64 --host-arch arm64 -us -uc -b 2>&1 | tail -5; then
      BUILD_OK=1
    fi
  else
    if dpkg-buildpackage -us -uc -b 2>&1 | tail -5; then
      BUILD_OK=1
    fi
  fi

  if [[ $BUILD_OK -eq 1 ]]; then
    ok "${PKG} built"
    ((SUCCESS++)) || true
  else
    err "${PKG} FAILED"
    ((FAILED++)) || true
  fi
done

# Déplacer les .deb vers output/debs
cd "${PACKAGES_DIR}"
mv *.deb "${OUTPUT_DIR}/" 2>/dev/null || true
rm -f *.changes *.buildinfo 2>/dev/null || true

# Résumé
echo ""
echo -e "${GOLD}${BOLD}════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  Build terminé !${NC}"
echo ""
echo -e "  Succès : ${SUCCESS}"
echo -e "  Échecs : ${FAILED}"
echo ""
echo -e "  Packages dans : ${OUTPUT_DIR}"
ls -la "${OUTPUT_DIR}"/*.deb 2>/dev/null | head -20 || true
echo ""
echo -e "${GOLD}${BOLD}════════════════════════════════════════════════════════${NC}"
