#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  setup-local-cache.sh — Configure apt-cacher-ng + local SecuBox repo
#  Usage: sudo bash scripts/setup-local-cache.sh
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

CACHE_DIR="${REPO_DIR}/cache"
LOCAL_REPO="${CACHE_DIR}/repo"
CACHE_PORT="3142"

RED='\033[0;31m'; CYAN='\033[0;36m'; GOLD='\033[0;33m'
GREEN='\033[0;32m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${CYAN}[cache]${NC} $*"; }
ok()   { echo -e "${GREEN}[  OK ]${NC} $*"; }
err()  { echo -e "${RED}[FAIL ]${NC} $*" >&2; exit 1; }
warn() { echo -e "${GOLD}[ WARN]${NC} $*"; }

[[ $EUID -ne 0 ]] && err "Ce script doit être exécuté en root (sudo)"

log "══════════════════════════════════════════════════════════"
log "Configuration du cache local APT + repo SecuBox"
log "══════════════════════════════════════════════════════════"

# ── 1. apt-cacher-ng pour cacher les paquets Debian ──────────────
log "1/4 Installation apt-cacher-ng..."
if ! dpkg -l apt-cacher-ng >/dev/null 2>&1; then
  apt-get update -q
  apt-get install -y -q apt-cacher-ng
  ok "apt-cacher-ng installé"
else
  ok "apt-cacher-ng déjà installé"
fi

# Configuration apt-cacher-ng
mkdir -p /etc/apt-cacher-ng/acng.conf.d
mkdir -p "${CACHE_DIR}/apt-cacher-ng"
chown apt-cacher-ng:apt-cacher-ng "${CACHE_DIR}/apt-cacher-ng"

cat > /etc/apt-cacher-ng/acng.conf.d/secubox.conf <<EOF
# SecuBox local cache config
Port: ${CACHE_PORT}
CacheDir: ${CACHE_DIR}/apt-cacher-ng
LogDir: /var/log/apt-cacher-ng
Remap-debrep: file:backends_debian /debian ; https://deb.debian.org/debian
Remap-uburep: file:backends_ubuntu /ubuntu ; http://archive.ubuntu.com/ubuntu
ExTreshold: 4
PassThroughPattern: .*
EOF

systemctl restart apt-cacher-ng
systemctl enable apt-cacher-ng
ok "apt-cacher-ng configuré sur port ${CACHE_PORT}"

# ── 2. Local repo pour paquets SecuBox ───────────────────────────
log "2/4 Configuration repo local SecuBox..."
mkdir -p "${LOCAL_REPO}/conf" "${LOCAL_REPO}/pool"

if ! dpkg -l reprepro >/dev/null 2>&1; then
  apt-get install -y -q reprepro gnupg
fi

# Config reprepro
cat > "${LOCAL_REPO}/conf/distributions" <<EOF
Origin: SecuBox-Local
Label: SecuBox Local Build Cache
Suite: bookworm
Codename: bookworm
Architectures: arm64 amd64 source
Components: main
Description: Local SecuBox packages for build testing

Origin: SecuBox-Local
Label: SecuBox Local Build Cache
Suite: trixie
Codename: trixie
Architectures: arm64 amd64 source
Components: main
Description: Local SecuBox packages for build testing
EOF

cat > "${LOCAL_REPO}/conf/options" <<EOF
verbose
basedir ${LOCAL_REPO}
ask-passphrase
EOF

ok "Repo local créé dans ${LOCAL_REPO}"

# ── 3. Serveur HTTP local pour le repo ───────────────────────────
log "3/4 Configuration serveur HTTP local..."

# nginx vhost pour le repo local (si nginx installé)
if command -v nginx >/dev/null && [[ -d /etc/nginx/sites-available ]]; then
  cat > /etc/nginx/sites-available/secubox-local-repo <<EOF
# SecuBox local APT repo
server {
    listen 8080;
    listen [::]:8080;
    server_name localhost;

    root ${LOCAL_REPO};
    autoindex on;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF
  ln -sf /etc/nginx/sites-available/secubox-local-repo /etc/nginx/sites-enabled/ 2>/dev/null || true
  nginx -t && systemctl reload nginx
  ok "Repo local accessible sur http://localhost:8080"
else
  # Fallback avec Python http.server
  cat > /etc/systemd/system/secubox-local-repo.service <<EOF
[Unit]
Description=SecuBox Local APT Repo Server
After=network.target

[Service]
Type=simple
WorkingDirectory=${LOCAL_REPO}
ExecStart=/usr/bin/python3 -m http.server 8080 --bind 0.0.0.0
Restart=always

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now secubox-local-repo
  ok "Repo local accessible sur http://localhost:8080 (Python http.server)"
fi

# ── 4. Scripts helper ────────────────────────────────────────────
log "4/4 Création scripts helper..."

# Script pour ajouter un .deb au repo local
cat > "${REPO_DIR}/scripts/local-repo-add.sh" <<'SCRIPT'
#!/usr/bin/env bash
# Ajouter un .deb au repo local
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
LOCAL_REPO="${REPO_DIR}/cache/repo"

SUITE="${1:-bookworm}"
shift || true

for DEB in "$@"; do
  [[ -f "$DEB" ]] || { echo "SKIP: $DEB (not found)"; continue; }
  reprepro -b "${LOCAL_REPO}" includedeb "${SUITE}" "$DEB"
  echo "OK: Added $(basename "$DEB") to ${SUITE}"
done
SCRIPT
chmod +x "${REPO_DIR}/scripts/local-repo-add.sh"

# Script pour builder et ajouter un package
cat > "${REPO_DIR}/scripts/build-add-local.sh" <<'SCRIPT'
#!/usr/bin/env bash
# Builder un package et l'ajouter au repo local
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

PKG="${1:-}"
SUITE="${2:-bookworm}"
ARCH="${3:-$(dpkg --print-architecture)}"

[[ -z "$PKG" ]] && { echo "Usage: $0 <package-name> [suite] [arch]"; exit 1; }

PKG_DIR="${REPO_DIR}/packages/${PKG}"
[[ -d "$PKG_DIR" ]] || { echo "Package not found: $PKG_DIR"; exit 1; }

cd "$PKG_DIR"

if [[ "$ARCH" == "arm64" ]] && [[ "$(uname -m)" != "aarch64" ]]; then
  dpkg-buildpackage -a arm64 --host-arch arm64 -us -uc -b
else
  dpkg-buildpackage -us -uc -b
fi

# Find generated .deb
cd "${REPO_DIR}/packages"
DEB=$(ls -t ${PKG}_*.deb 2>/dev/null | head -1)
[[ -n "$DEB" ]] && bash "${SCRIPT_DIR}/local-repo-add.sh" "$SUITE" "$DEB"
SCRIPT
chmod +x "${REPO_DIR}/scripts/build-add-local.sh"

ok "Scripts helper créés"

# ── Résumé ───────────────────────────────────────────────────────
echo ""
echo -e "${GOLD}${BOLD}════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  Cache local configuré !${NC}"
echo ""
echo -e "  APT Cache (apt-cacher-ng) : http://localhost:${CACHE_PORT}"
echo -e "  Local Repo                : http://localhost:8080"
echo -e "  Repo path                 : ${LOCAL_REPO}"
echo ""
echo -e "${CYAN}  Commandes utiles :${NC}"
echo -e "    # Builder et ajouter un package au repo local"
echo -e "    bash scripts/build-add-local.sh secubox-crowdsec bookworm"
echo ""
echo -e "    # Ajouter un .deb existant"
echo -e "    bash scripts/local-repo-add.sh bookworm packages/*.deb"
echo ""
echo -e "    # Builder une image avec le cache local"
echo -e "    sudo bash image/build-image.sh --board vm-x64 --local-cache"
echo -e "${GOLD}${BOLD}════════════════════════════════════════════════════════${NC}"
