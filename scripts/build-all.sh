#!/bin/bash
# Build all SecuBox packages locally
# Usage: ./scripts/build-all.sh [output_dir]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${1:-$BASE_DIR/output}"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${CYAN}[BUILD]${NC} $1"; }
ok() { echo -e "${GREEN}[OK]${NC} $1"; }
err() { echo -e "${RED}[ERR]${NC} $1"; }

mkdir -p "$OUTPUT_DIR"

# Find all packages
PACKAGES=$(find "$BASE_DIR/packages" -maxdepth 1 -type d -name "secubox-*" | sort)
TOTAL=$(echo "$PACKAGES" | wc -l)
COUNT=0
FAILED=0

log "Building $TOTAL packages to $OUTPUT_DIR"
echo ""

for pkg_dir in $PACKAGES; do
    pkg=$(basename "$pkg_dir")
    COUNT=$((COUNT + 1))

    if [ ! -f "$pkg_dir/debian/control" ]; then
        err "[$COUNT/$TOTAL] $pkg - no debian/control"
        FAILED=$((FAILED + 1))
        continue
    fi

    log "[$COUNT/$TOTAL] Building $pkg..."

    cd "$pkg_dir"

    # Clean previous build
    rm -rf debian/.debhelper debian/"$pkg" 2>/dev/null || true

    # Build
    if dpkg-buildpackage -us -uc -b > /tmp/build-$pkg.log 2>&1; then
        # Move .deb files
        mv ../*.deb "$OUTPUT_DIR/" 2>/dev/null || true
        rm -f ../*.buildinfo ../*.changes 2>/dev/null || true
        ok "$pkg"
    else
        err "$pkg - build failed (see /tmp/build-$pkg.log)"
        FAILED=$((FAILED + 1))
    fi

    cd "$BASE_DIR"
done

echo ""
log "Build complete: $((TOTAL - FAILED))/$TOTAL succeeded"

if [ $FAILED -gt 0 ]; then
    err "$FAILED packages failed to build"
    exit 1
fi

# Generate SHA256SUMS
cd "$OUTPUT_DIR"
sha256sum *.deb > SHA256SUMS 2>/dev/null || true

log "Output in $OUTPUT_DIR"
ls -lh "$OUTPUT_DIR"/*.deb 2>/dev/null | head -20
echo "..."
echo "Total: $(ls -1 "$OUTPUT_DIR"/*.deb 2>/dev/null | wc -l) packages"
