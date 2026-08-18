#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# ══════════════════════════════════════════════════════════════════
#  build-packages.sh — Build all SecuBox .deb packages
#  Usage: bash scripts/build-packages.sh [bookworm|trixie] [arm64|amd64]
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
PACKAGES_DIR="${REPO_DIR}/packages"
OUTPUT_DIR="${REPO_DIR}/output/debs"

# Parse positional + flags
SUITE="${1:-bookworm}"; shift || true
ARCH="${1:-$(dpkg --print-architecture)}"; shift || true

FILTER=""
DRY_RUN=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --filter)   FILTER="$2"; shift 2 ;;
    --dry-run)  DRY_RUN=1; shift ;;
    *)          err "Unknown flag: $1"; exit 2 ;;
  esac
done

RED='\033[0;31m'; CYAN='\033[0;36m'; GOLD='\033[0;33m'
GREEN='\033[0;32m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${CYAN}[build]${NC} $*"; }
ok()   { echo -e "${GREEN}[  OK ]${NC} $*"; }
err()  { echo -e "${RED}[FAIL ]${NC} $*" >&2; }
warn() { echo -e "${GOLD}[ WARN]${NC} $*"; }

# Auto-discover all secubox-* packages that have a debian/control file.
# (Previously a hardcoded list that fell out of sync as new packages were
# added — 18+ packages were silently never built. Issue surfaced on
# 2026-05-27 during the consolidation deploy.)
#
# Build order: secubox-core first (universal Depends:), metapackages
# (secubox-full / secubox-lite) last, everything else alphabetical
# between them. The exact order doesn't matter for dpkg-buildpackage
# (each package builds independently), but the ordering keeps the build
# log readable and surfaces core/meta build failures early/late
# respectively.
mapfile -t _ALL_PKGS < <(
  for d in "${PACKAGES_DIR}"/secubox-*/; do
    [[ -d "$d" ]] || continue
    name=$(basename "$d")
    [[ -f "${d}debian/control" ]] && echo "$name"
  done | sort
)
PACKAGES=()
[[ -f "${PACKAGES_DIR}/secubox-core/debian/control" ]] && PACKAGES+=("secubox-core")
for _p in "${_ALL_PKGS[@]}"; do
  case "$_p" in
    secubox-core|secubox-full|secubox-lite) ;;
    *) PACKAGES+=("$_p") ;;
  esac
done
[[ -f "${PACKAGES_DIR}/secubox-full/debian/control" ]] && PACKAGES+=("secubox-full")
[[ -f "${PACKAGES_DIR}/secubox-lite/debian/control" ]] && PACKAGES+=("secubox-lite")
unset _ALL_PKGS _p

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

if [[ -n "$FILTER" ]]; then
  if [[ ! -f "$FILTER" ]]; then
    err "Filter manifest not found: $FILTER"
    exit 1
  fi
  mapfile -t ALLOWED < <(jq -r '.[]' "$FILTER")
  log "Filter active: ${#ALLOWED[@]} packages"
fi

is_allowed() {
  local pkg="$1"
  [[ -z "$FILTER" ]] && return 0
  for a in "${ALLOWED[@]}"; do [[ "$a" == "$pkg" ]] && return 0; done
  return 1
}

for PKG in "${PACKAGES[@]}"; do
  PKG_DIR="${PACKAGES_DIR}/${PKG}"

  if [[ ! -d "${PKG_DIR}/debian" ]]; then
    warn "SKIP ${PKG} — pas de debian/"
    continue
  fi

  if ! is_allowed "$PKG"; then
    continue
  fi
  if [[ $DRY_RUN -eq 1 ]]; then
    log "DRY-RUN would build: $PKG"
    continue
  fi

  log "Building ${BOLD}${PKG}${NC}..."

  cd "${PKG_DIR}"

  # Rendre rules exécutable
  chmod +x debian/rules 2>/dev/null || true

  # Build le package with timeout and proper exit code handling
  # Use a writable log directory (avoid /tmp permission issues from previous root runs)
  LOG_DIR="${REPO_DIR}/output/logs"
  mkdir -p "$LOG_DIR" 2>/dev/null || LOG_DIR="/tmp/secubox-build-$$"
  mkdir -p "$LOG_DIR" 2>/dev/null || true
  BUILD_LOG="${LOG_DIR}/build-${PKG}.log"
  BUILD_OK=0

  # Use timeout to prevent infinite hangs (5 minutes per package)
  TIMEOUT_CMD="timeout --kill-after=30s 300s"

  # -d skips the build-dependency check: every SecuBox package is
  # Architecture: all (dh just copies files), so the Build-Depends need not be
  # installed on the build host. Without -d, packages declaring deps absent
  # here (e.g. python3-all version mismatch) fail dpkg-checkbuilddeps and were
  # silently dropped from the repo — incl. secubox-core. (CLAUDE.md mandates -d.)
  if [[ "$ARCH" == "arm64" ]] && [[ "$(uname -m)" != "aarch64" ]]; then
    # Cross-compile pour arm64
    if $TIMEOUT_CMD dpkg-buildpackage -a arm64 --host-arch arm64 -us -uc -b -d > "$BUILD_LOG" 2>&1; then
      BUILD_OK=1
    fi
  else
    if $TIMEOUT_CMD dpkg-buildpackage -us -uc -b -d > "$BUILD_LOG" 2>&1; then
      BUILD_OK=1
    fi
  fi

  if [[ $BUILD_OK -eq 1 ]]; then
    ok "${PKG} built"
    ((SUCCESS++)) || true
  else
    # Show last 10 lines of log for debugging
    err "${PKG} FAILED (see $BUILD_LOG)"
    tail -10 "$BUILD_LOG" 2>/dev/null | sed 's/^/    /' || true
    ((FAILED++)) || true
  fi
done

# Déplacer les .deb vers output/debs (pas en dry-run)
if [[ $DRY_RUN -eq 0 ]]; then
  cd "${PACKAGES_DIR}"
  mv *.deb "${OUTPUT_DIR}/" 2>/dev/null || true
  rm -f *.changes *.buildinfo 2>/dev/null || true
fi

# Résumé
echo ""
echo -e "${GOLD}${BOLD}════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  Build terminé !${NC}"
echo ""
echo -e "  Succès : ${SUCCESS}"
echo -e "  Échecs : ${FAILED}"
if [[ $DRY_RUN -eq 0 ]]; then
  echo ""
  echo -e "  Packages dans : ${OUTPUT_DIR}"
  ls -la "${OUTPUT_DIR}"/*.deb 2>/dev/null | head -20 || true
fi
echo ""
echo -e "${GOLD}${BOLD}════════════════════════════════════════════════════════${NC}"
