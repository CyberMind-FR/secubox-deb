#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

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
WWW_PUSHED=0   # au moins un module a déposé des assets www/ → purger le cache WAF

[[ -z "$PKG" || -z "$HOST" ]] && {
  echo "Usage: bash scripts/deploy.sh <package|--all> <user@host> [--restart]"
  exit 1
}

ssh_run() { ssh -o StrictHostKeyChecking=no "$HOST" "$@"; }

# Repertoire d'installation REEL du module, lu dans debian/rules — la seule
# source de verite.
#
# Un paquet `secubox-<x>` n'installe PAS dans /usr/lib/secubox/secubox-<x> mais
# dans /usr/lib/secubox/<x> (et parfois ailleurs : secubox-yggdrasil s'installe
# dans `mesh`). deploy.sh visait /usr/lib/secubox/$pkg : sur 126 paquets portant
# un dossier api/, 126 recevaient donc leur code Python dans un repertoire que
# le service ne lit jamais. Seul www/ arrivait a bon port, ce qui rendait la
# panne invisible — l'interface changeait, l'API non.
module_dir() {
  local pkg="$1" d
  d=$(grep -ohE "usr/lib/secubox/[a-z0-9_-]+" "$REPO/packages/$pkg/debian/rules" 2>/dev/null \
      | head -1 | sed "s|.*/||")
  [[ -n "$d" ]] && { echo "$d"; return; }
  echo "${pkg#secubox-}"   # repli : la convention, si rules ne dit rien
}

# Purge du cache média du WAF après avoir déposé des assets www/. Le cache de
# sbxwaf (TTL 1 h) sert CSS/JS/images/polices ; un asset redéployé dont l'amont
# ne change pas l'ETag reste servi périmé jusqu'à la fin du TTL (le « vieux
# skin » après déploiement). Best-effort : absence de wafctl = simple no-op.
purge_waf_cache() {
  [[ $WWW_PUSHED -eq 1 ]] || return 0
  log "Purge du cache média WAF (assets www/ mis à jour)..."
  ssh_run "command -v wafctl >/dev/null && wafctl purge-cache || true"
}

deploy_pkg() {
  local pkg="$1"
  local pkg_dir="$REPO/packages/$pkg"

  [[ -d "$pkg_dir" ]] || err "Package introuvable: $pkg_dir"

  local svc="${pkg}"  # service name = package name

  log "Déploiement $pkg → $HOST"

  # ── Copier l'API Python (dans le repertoire REELLEMENT lu par le service) ──
  local mod; mod="$(module_dir "$pkg")"
  if [[ -d "${pkg_dir}/api" ]]; then
    log "  api → /usr/lib/secubox/${mod}/api"
    ssh_run "mkdir -p /usr/lib/secubox/${mod}/api"
    rsync -az --delete -e "ssh -o StrictHostKeyChecking=no" \
      "${pkg_dir}/api/" "${HOST}:/usr/lib/secubox/${mod}/api/"
  fi

  # ── Copier le frontend www/ ──
  # NOTE: Do NOT use --delete here as multiple packages share /usr/share/secubox/www/
  if [[ -d "${pkg_dir}/www" ]]; then
    ssh_run "mkdir -p /usr/share/secubox/www"
    rsync -az -e "ssh -o StrictHostKeyChecking=no" \
      "${pkg_dir}/www/" "${HOST}:/usr/share/secubox/www/"
    WWW_PUSHED=1
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
  purge_waf_cache
  ok "Déploiement complet terminé"
else
  deploy_pkg "$PKG"
  [[ $RESTART -eq 1 ]] && ssh_run "systemctl reload nginx 2>/dev/null || true"
  purge_waf_cache
fi
