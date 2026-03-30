#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  build-all-local.sh — Build ALL SecuBox packages and add to local repo
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

# ══════════════════════════════════════════════════════════════════
# Discover all packages dynamically
# ══════════════════════════════════════════════════════════════════
discover_packages() {
    local core_pkg="secubox-core"
    local meta_pkgs="secubox-full secubox-lite"
    local all_pkgs=()
    local other_pkgs=()

    # Find all packages with debian/ directory
    for pkg_dir in "${PACKAGES_DIR}"/secubox-*/; do
        [ -d "${pkg_dir}/debian" ] || continue
        local pkg_name=$(basename "$pkg_dir")
        all_pkgs+=("$pkg_name")
    done

    # Separate into: core, others, metapackages
    for pkg in "${all_pkgs[@]}"; do
        if [[ "$pkg" == "$core_pkg" ]]; then
            continue  # Core handled separately
        elif [[ " $meta_pkgs " =~ " $pkg " ]]; then
            continue  # Metapackages handled last
        else
            other_pkgs+=("$pkg")
        fi
    done

    # Build order: core first, then others, then metapackages
    PACKAGES=("$core_pkg")
    PACKAGES+=("${other_pkgs[@]}")
    for meta in $meta_pkgs; do
        [ -d "${PACKAGES_DIR}/${meta}/debian" ] && PACKAGES+=("$meta")
    done

    echo "${#PACKAGES[@]} packages found"
}

log "══════════════════════════════════════════════════════════"
log "Build ALL SecuBox packages for ${BOLD}${SUITE}/${ARCH}${NC}"
log "══════════════════════════════════════════════════════════"

# Discover packages
discover_packages

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
FAILED_PKGS=()

log "Building ${#PACKAGES[@]} packages..."
echo ""

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
    SUCCESS=$((SUCCESS + 1))
  else
    err "${PKG} FAILED"
    FAILED=$((FAILED + 1))
    FAILED_PKGS+=("$PKG")
  fi
done

# Ajouter tous les .deb au repo local
cd "${PACKAGES_DIR}"
DEBS=$(ls -1 *.deb 2>/dev/null || true)

if [[ -n "$DEBS" ]]; then
  echo ""
  log "Adding packages to local repo..."
  ADDED=0
  for DEB in $DEBS; do
    if reprepro -b "${LOCAL_REPO}" includedeb "${SUITE}" "${DEB}" 2>/dev/null; then
      ok "Added ${DEB}"
      ADDED=$((ADDED + 1))
    else
      warn "Failed to add ${DEB} (may already exist)"
    fi
  done
  log "Added ${ADDED} packages to repo"
fi

# Liste des packages dans le repo
REPO_COUNT=$(find "${LOCAL_REPO}/pool" -name "*.deb" 2>/dev/null | wc -l)

# Résumé
echo ""
echo -e "${GOLD}${BOLD}════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  Build terminé !${NC}"
echo ""
echo -e "  Packages trouvés : ${#PACKAGES[@]}"
echo -e "  Succès          : ${SUCCESS}"
echo -e "  Échecs          : ${FAILED}"
echo -e "  Dans le repo    : ${REPO_COUNT}"
echo ""
if [[ ${#FAILED_PKGS[@]} -gt 0 ]]; then
  echo -e "${RED}  Packages en échec :${NC}"
  for pkg in "${FAILED_PKGS[@]}"; do
    echo -e "    - ${pkg}"
  done
  echo ""
fi
echo -e "  Repo local : ${LOCAL_REPO}"
echo ""
echo -e "${CYAN}  Pour builder une image avec ces packages :${NC}"
echo -e "    sudo bash image/build-live-usb.sh --kiosk --local-cache"
echo -e "${GOLD}${BOLD}════════════════════════════════════════════════════════${NC}"
