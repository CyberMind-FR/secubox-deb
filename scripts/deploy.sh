#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  scripts/deploy.sh — Déploiement SSH sur board SecuBox
#
#  Usage :
#    bash scripts/deploy.sh secubox-crowdsec root@192.168.1.1
#    bash scripts/deploy.sh --all root@192.168.1.1
#    bash scripts/deploy.sh secubox-crowdsec root@192.168.1.1 --restart
# ══════════════════════════════════════════════════════════════════
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"

CYAN='\033[0;36m'; GREEN='\033[0;32m'; GOLD='\033[0;33m'
RED='\033[0;31m'; NC='\033[0m'

log()  { echo -e "${CYAN}[deploy]${NC} $*"; }
ok()   { echo -e "${GREEN}[   OK]${NC} $*"; }
err()  { echo -e "${RED}[ FAIL]${NC} $*" >&2; exit 1; }

PKG="${1:-}"
HOST="${2:-}"
RESTART=0
[[ "${3:-}" == "--restart" ]] && RESTART=1

[[ -z "$PKG" || -z "$HOST" ]] && {
  echo "Usage: bash scripts/deploy.sh <package|--all> <user@host> [--restart]"
  exit 1
}

ssh_run() { ssh -o StrictHostKeyChecking=no "$HOST" "$@"; }

deploy_pkg() {
  local pkg="$1"
  local pkg_dir="$REPO/packages/$pkg"

  [[ -d "$pkg_dir" ]] || err "Package introuvable: $pkg_dir"

  local svc="${pkg}"  # service name = package name

  log "Déploiement $pkg → $HOST"

  # ── Copier l'API Python ──
  ssh_run "mkdir -p /usr/lib/secubox/${pkg}/api"
  rsync -az --delete -e "ssh -o StrictHostKeyChecking=no" \
    "${pkg_dir}/api/" "${HOST}:/usr/lib/secubox/${pkg}/api/"

  # ── Copier le frontend www/ ──
  if [[ -d "${pkg_dir}/www" ]]; then
    ssh_run "mkdir -p /usr/share/secubox/www"
    rsync -az --delete -e "ssh -o StrictHostKeyChecking=no" \
      "${pkg_dir}/www/" "${HOST}:/usr/share/secubox/www/"
  fi

  # ── Copier secubox_core si c'est le core ──
  if [[ "$pkg" == "secubox-core" ]]; then
    rsync -az --delete -e "ssh -o StrictHostKeyChecking=no" \
      "${REPO}/common/secubox_core/" \
      "${HOST}:/usr/lib/python3/dist-packages/secubox_core/"
  fi

  # ── Redémarrer le service ──
  if [[ $RESTART -eq 1 ]]; then
    log "Restart $svc..."
    ssh_run "systemctl restart ${svc} 2>/dev/null || true"
    ssh_run "systemctl is-active ${svc} && echo '  service: active' || echo '  service: FAILED'"
  fi

  ok "$pkg déployé"
}

if [[ "$PKG" == "--all" ]]; then
  # Core en premier
  deploy_pkg "secubox-core"
  # Puis tous les autres
  for d in "$REPO/packages"/secubox-*/; do
    pkg=$(basename "$d")
    [[ "$pkg" == "secubox-core" ]] && continue
    deploy_pkg "$pkg"
  done
  # Recharger nginx
  ssh_run "systemctl reload nginx 2>/dev/null || true"
  ok "Déploiement complet terminé"
else
  deploy_pkg "$PKG"
  [[ $RESTART -eq 1 ]] && ssh_run "systemctl reload nginx 2>/dev/null || true"
fi
