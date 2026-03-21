#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  SecuBox APT Repo — Gestion du repository avec reprepro
#  Usage : bash repo-manage.sh <command> [args]
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

REPO_BASE="${REPO_BASE:-/var/lib/secubox-repo}"
REPO_CONF="${REPO_BASE}/conf"
REPO_OUT="${REPO_OUT:-/var/www/apt.secubox.in}"
GPG_HOME="${REPO_BASE}/gpg"

RED='\033[0;31m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; GOLD='\033[0;33m'; NC='\033[0m'
log() { echo -e "${CYAN}[repo]${NC} $*"; }
ok()  { echo -e "${GREEN}[OK]${NC} $*"; }
err() { echo -e "${RED}[ERR]${NC} $*" >&2; exit 1; }

usage() {
  cat <<EOF
SecuBox APT Repository Manager

Usage: repo-manage.sh <command> [args]

Commands:
  init                    Initialiser le repository
  add <dist> <deb...>     Ajouter des packages .deb
  remove <dist> <pkg>     Supprimer un package
  list <dist>             Lister les packages
  update                  Mettre à jour les index
  export-key              Exporter la clé publique GPG
  sync <dest>             Synchroniser vers un serveur distant

Distributions: bookworm, trixie

Examples:
  repo-manage.sh init
  repo-manage.sh add bookworm *.deb
  repo-manage.sh list bookworm
  repo-manage.sh sync user@apt.secubox.in:/var/www/apt.secubox.in/

EOF
  exit 0
}

cmd_init() {
  log "Initialisation du repository..."

  mkdir -p "${REPO_BASE}" "${REPO_CONF}" "${REPO_OUT}" "${GPG_HOME}"
  chmod 700 "${GPG_HOME}"

  # Copier la config si pas présente
  SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
  if [[ -f "${SCRIPT_DIR}/../conf/distributions" ]]; then
    cp "${SCRIPT_DIR}/../conf/distributions" "${REPO_CONF}/"
    cp "${SCRIPT_DIR}/../conf/options" "${REPO_CONF}/"
  fi

  # Générer la clé GPG si nécessaire
  if ! gpg --homedir "${GPG_HOME}" --list-keys "packages@secubox.in" &>/dev/null; then
    log "Génération clé GPG..."
    GPG_HOME="${GPG_HOME}" EXPORT_DIR="${REPO_OUT}" bash "${SCRIPT_DIR}/generate-gpg-key.sh"
  fi

  ok "Repository initialisé dans ${REPO_BASE}"
}

cmd_add() {
  local dist="$1"
  shift

  [[ -z "${dist}" ]] && err "Distribution requise (bookworm, trixie)"
  [[ $# -eq 0 ]] && err "Au moins un fichier .deb requis"

  log "Ajout de $# package(s) à ${dist}..."

  for deb in "$@"; do
    if [[ -f "$deb" ]]; then
      reprepro -b "${REPO_BASE}" includedeb "${dist}" "$deb"
      ok "Ajouté : $(basename "$deb")"
    else
      log "Fichier non trouvé : $deb"
    fi
  done
}

cmd_remove() {
  local dist="$1"
  local pkg="$2"

  [[ -z "${dist}" ]] && err "Distribution requise"
  [[ -z "${pkg}" ]] && err "Nom du package requis"

  log "Suppression de ${pkg} de ${dist}..."
  reprepro -b "${REPO_BASE}" remove "${dist}" "${pkg}"
  ok "Supprimé : ${pkg}"
}

cmd_list() {
  local dist="${1:-bookworm}"

  log "Packages dans ${dist} :"
  reprepro -b "${REPO_BASE}" list "${dist}"
}

cmd_update() {
  log "Mise à jour des index..."
  reprepro -b "${REPO_BASE}" export
  ok "Index mis à jour"
}

cmd_export_key() {
  log "Export clé publique..."
  gpg --homedir "${GPG_HOME}" --armor --export "packages@secubox.in" > "${REPO_OUT}/secubox-keyring.gpg"
  gpg --homedir "${GPG_HOME}" --export "packages@secubox.in" > "${REPO_OUT}/secubox-keyring.gpg.bin"
  ok "Clé exportée vers ${REPO_OUT}/secubox-keyring.gpg"
}

cmd_sync() {
  local dest="$1"

  [[ -z "${dest}" ]] && err "Destination requise (user@host:/path/)"

  log "Synchronisation vers ${dest}..."
  rsync -avz --delete "${REPO_OUT}/" "${dest}"
  ok "Synchronisation terminée"
}

# Main
[[ $# -eq 0 ]] && usage

CMD="$1"
shift

case "${CMD}" in
  init)       cmd_init ;;
  add)        cmd_add "$@" ;;
  remove)     cmd_remove "$@" ;;
  list)       cmd_list "$@" ;;
  update)     cmd_update ;;
  export-key) cmd_export_key ;;
  sync)       cmd_sync "$@" ;;
  help|-h|--help) usage ;;
  *) err "Commande inconnue: ${CMD}" ;;
esac
