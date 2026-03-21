#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  scripts/port-frontend.sh
#  Copie les htdocs depuis le repo source secubox-openwrt
#  et lance rewrite-xhr.py dessus.
#
#  Usage :
#    bash scripts/port-frontend.sh crowdsec-dashboard
#    bash scripts/port-frontend.sh --all
#    SECUBOX_SRC=/path/to/secubox-openwrt bash scripts/port-frontend.sh wireguard-dashboard
# ══════════════════════════════════════════════════════════════════
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"

CYAN='\033[0;36m'; GREEN='\033[0;32m'; GOLD='\033[0;33m'
RED='\033[0;31m'; NC='\033[0m'

log()  { echo -e "${CYAN}[port]${NC} $*"; }
ok()   { echo -e "${GREEN}[  OK]${NC} $*"; }
warn() { echo -e "${GOLD}[ WARN]${NC} $*"; }
err()  { echo -e "${RED}[FAIL]${NC} $*" >&2; exit 1; }

# ── Source repo ───────────────────────────────────────────────────
SRC_REPO="${SECUBOX_SRC:-}"
if [[ -z "$SRC_REPO" ]]; then
  # Chercher un clone local
  for candidate in \
    "${REPO}/../secubox-openwrt" \
    "/tmp/secubox-src" \
    "${HOME}/src/secubox-openwrt"; do
    if [[ -d "$candidate/package/secubox" ]]; then
      SRC_REPO="$candidate"
      break
    fi
  done
fi

if [[ -z "$SRC_REPO" ]]; then
  warn "Repo source introuvable. Clonage shallow..."
  SRC_REPO="/tmp/secubox-openwrt-src"
  if [[ ! -d "$SRC_REPO" ]]; then
    git clone --depth=1 \
      https://github.com/gkerma/secubox-openwrt.git \
      "$SRC_REPO" 2>&1 | tail -3
  fi
fi
log "Source repo : $SRC_REPO"

# ── Mapping luci-app-X → secubox-Y ───────────────────────────────
declare -A MODULE_MAP=(
  ["crowdsec-dashboard"]="crowdsec"
  ["netdata-dashboard"]="netdata"
  ["wireguard-dashboard"]="wireguard"
  ["network-modes"]="netmodes"
  ["client-guardian"]="nac"
  ["auth-guardian"]="auth"
  ["bandwidth-manager"]="qos"
  ["media-flow"]="mediaflow"
  ["cdn-cache"]="cdn"
  ["vhost-manager"]="vhost"
  ["system-hub"]="system"
  ["netifyd-dashboard"]="dpi"
  ["secubox"]="hub"
)

port_module() {
  local luci_name="$1"
  local deb_name="${MODULE_MAP[$luci_name]:-}"

  if [[ -z "$deb_name" ]]; then
    err "Module inconnu: $luci_name. Modules disponibles: ${!MODULE_MAP[*]}"
  fi

  local src_htdocs="$SRC_REPO/package/secubox/luci-app-${luci_name}/htdocs"
  if [[ ! -d "$src_htdocs" ]]; then
    err "htdocs introuvable: $src_htdocs"
  fi

  local dst_www="$REPO/packages/secubox-${deb_name}/www"
  mkdir -p "$dst_www"

  log "Copie $luci_name → secubox-$deb_name/www/"
  rsync -a --delete "${src_htdocs}/" "${dst_www}/"

  # Réécriture XHR
  log "Réécriture appels ubus → REST..."
  python3 "$REPO/scripts/rewrite-xhr.py" "${dst_www}/"

  ok "secubox-${deb_name}/www/ prêt"
}

# ── Main ──────────────────────────────────────────────────────────
if [[ "${1:-}" == "--all" ]]; then
  for luci_name in "${!MODULE_MAP[@]}"; do
    echo ""
    port_module "$luci_name"
  done
  echo ""
  ok "Tous les frontends portés."
elif [[ -n "${1:-}" ]]; then
  port_module "$1"
else
  echo "Usage: bash scripts/port-frontend.sh <luci-module-name>"
  echo "       bash scripts/port-frontend.sh --all"
  echo ""
  echo "Modules disponibles:"
  for k in "${!MODULE_MAP[@]}"; do
    echo "  $k → secubox-${MODULE_MAP[$k]}"
  done
fi
