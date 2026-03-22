#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  SecuBox APT Repo — Local publish for testing
#  Usage : bash local-publish.sh [--dist bookworm] [--serve]
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PACKAGES_DIR="${REPO_ROOT}/packages"
OUTPUT_DIR="${REPO_ROOT}/output"
LOCAL_REPO="${REPO_ROOT}/local-repo"
DIST="${DIST:-bookworm}"
SERVE="${SERVE:-false}"
SERVE_PORT="${SERVE_PORT:-8888}"

RED='\033[0;31m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; GOLD='\033[0;33m'; NC='\033[0m'
log() { echo -e "${CYAN}[publish]${NC} $*"; }
ok()  { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${GOLD}[WARN]${NC} $*"; }
err() { echo -e "${RED}[ERR]${NC} $*" >&2; exit 1; }

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dist)    DIST="$2"; shift 2 ;;
    --serve)   SERVE="true"; shift ;;
    --port)    SERVE_PORT="$2"; shift 2 ;;
    --output)  OUTPUT_DIR="$2"; shift 2 ;;
    *)         err "Unknown option: $1" ;;
  esac
done

log "Local APT Repository Publishing"
log "================================"

# Check for reprepro
if ! command -v reprepro &>/dev/null; then
  err "reprepro not found. Install with: sudo apt install reprepro"
fi

# Check for .deb files
DEB_COUNT=$(find "${OUTPUT_DIR}" -name "*.deb" 2>/dev/null | wc -l)
if [[ "${DEB_COUNT}" -eq 0 ]]; then
  warn "No .deb files found in ${OUTPUT_DIR}"
  log "Building packages first..."
  if [[ -x "${REPO_ROOT}/scripts/build-all.sh" ]]; then
    bash "${REPO_ROOT}/scripts/build-all.sh"
  else
    err "No packages to publish and build script not found"
  fi
  DEB_COUNT=$(find "${OUTPUT_DIR}" -name "*.deb" 2>/dev/null | wc -l)
fi

log "Found ${DEB_COUNT} .deb packages"

# Setup local repository structure
log "Setting up local repository..."
mkdir -p "${LOCAL_REPO}"/{conf,db,dists,pool}

# Create reprepro config
cat > "${LOCAL_REPO}/conf/distributions" <<EOF
Origin: SecuBox-Local
Label: SecuBox-Local
Suite: ${DIST}
Codename: ${DIST}
Architectures: amd64 arm64 source
Components: main
Description: SecuBox local test repository
EOF

cat > "${LOCAL_REPO}/conf/options" <<EOF
verbose
basedir ${LOCAL_REPO}
EOF

# Add packages
log "Adding packages to repository..."
ADDED=0
FAILED=0

for deb in "${OUTPUT_DIR}"/*.deb; do
  [[ -f "$deb" ]] || continue
  pkg_name=$(basename "$deb")

  if reprepro -b "${LOCAL_REPO}" includedeb "${DIST}" "$deb" 2>/dev/null; then
    echo "  ✓ ${pkg_name}"
    ((ADDED++))
  else
    echo "  ✗ ${pkg_name} (failed)"
    ((FAILED++))
  fi
done

log "Added ${ADDED} packages, ${FAILED} failed"

# Generate install script
cat > "${LOCAL_REPO}/install-local.sh" <<EOF
#!/bin/bash
# Local SecuBox repository installer
set -e

REPO_URL="\${1:-http://localhost:${SERVE_PORT}}"

echo "Adding local SecuBox repository..."
echo "deb [trusted=yes] \${REPO_URL} ${DIST} main" | \\
  sudo tee /etc/apt/sources.list.d/secubox-local.list

sudo apt-get update
echo ""
echo "Local repository added. Install with:"
echo "  sudo apt install secubox-full"
EOF
chmod +x "${LOCAL_REPO}/install-local.sh"

# Generate index.html
cat > "${LOCAL_REPO}/index.html" <<EOF
<!DOCTYPE html>
<html>
<head>
  <title>SecuBox Local Repository</title>
  <style>
    body { font-family: sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
    code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }
    pre { background: #1e1e2e; color: #cdd6f4; padding: 15px; border-radius: 5px; }
    h1 { color: #89b4fa; }
  </style>
</head>
<body>
  <h1>🧪 SecuBox Local Test Repository</h1>
  <p>${ADDED} packages for ${DIST}</p>

  <h2>Quick Install</h2>
  <pre>curl -fsSL http://localhost:${SERVE_PORT}/install-local.sh | bash</pre>

  <h2>Manual Install</h2>
  <pre>
echo "deb [trusted=yes] http://localhost:${SERVE_PORT} ${DIST} main" | \\
  sudo tee /etc/apt/sources.list.d/secubox-local.list
sudo apt update
sudo apt install secubox-full
  </pre>

  <h2>Contents</h2>
  <ul>
    <li><a href="/dists/">Distributions</a></li>
    <li><a href="/pool/">Package Pool</a></li>
  </ul>
</body>
</html>
EOF

ok "Local repository ready at: ${LOCAL_REPO}"

# List packages
log "Packages in repository:"
reprepro -b "${LOCAL_REPO}" list "${DIST}" | head -20
echo "  ... (${ADDED} total)"

# Serve if requested
if [[ "${SERVE}" == "true" ]]; then
  log "Starting local web server on port ${SERVE_PORT}..."
  log "Repository URL: http://localhost:${SERVE_PORT}"
  log "Install with: curl -fsSL http://localhost:${SERVE_PORT}/install-local.sh | bash"
  log ""
  log "Press Ctrl+C to stop"

  cd "${LOCAL_REPO}"
  python3 -m http.server "${SERVE_PORT}"
else
  echo ""
  echo -e "${GREEN}════════════════════════════════════════════${NC}"
  echo "  Local repository created: ${LOCAL_REPO}"
  echo ""
  echo "  To serve locally:"
  echo "    cd ${LOCAL_REPO} && python3 -m http.server ${SERVE_PORT}"
  echo ""
  echo "  Or run with --serve flag:"
  echo "    bash local-publish.sh --serve"
  echo ""
  echo "  Then on target machine:"
  echo "    curl -fsSL http://<your-ip>:${SERVE_PORT}/install-local.sh | bash"
  echo -e "${GREEN}════════════════════════════════════════════${NC}"
fi
