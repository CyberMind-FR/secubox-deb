#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# SecuBox Remote UI — deploy.sh
# Déploie/met à jour le dashboard sur un RPi Zero W déjà configuré
#
# CyberMind — https://cybermind.fr
# Author: Gérald Kerma <gandalf@gk2.net>
# License: Proprietary / ANSSI CSPN candidate
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="1.0.0"
INDEX_HTML="$SCRIPT_DIR/index.html"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${GREEN}[deploy]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }
err()  { echo -e "${RED}[error]${NC} $*" >&2; }

# Valeurs par défaut
HOST=""
USER="secubox"
PORT=22
API_URL=""
API_PASS=""
SIMULATE=""

# ══════════════════════════════════════════════════════════════════════════════
# AIDE
# ══════════════════════════════════════════════════════════════════════════════

usage() {
    cat << EOF
SecuBox Remote UI — Déploiement Dashboard RPi Zero W

Usage: $0 [OPTIONS]

Options requises:
  -h, --host HOST         Adresse IP ou hostname du RPi Zero W

Options facultatives:
  -u, --user USER         Utilisateur SSH (défaut: $USER)
  -p, --port PORT         Port SSH (défaut: $PORT)
  --api-url URL           URL de l'API SecuBox (ex: http://192.168.1.1:8000)
  --api-pass PASS         Mot de passe API pour le dashboard
  --sim                   Activer le mode simulation (hors-ligne)
  --no-sim                Désactiver le mode simulation
  --help                  Afficher cette aide

Exemples:
  $0 -h secubox-round.local --api-url http://192.168.1.1:8000 --api-pass motdepasse
  $0 -h 192.168.1.42 -u pi --sim

EOF
    exit 0
}

# ══════════════════════════════════════════════════════════════════════════════
# PARSING ARGUMENTS
# ══════════════════════════════════════════════════════════════════════════════

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--host)     HOST="$2"; shift 2 ;;
        -u|--user)     USER="$2"; shift 2 ;;
        -p|--port)     PORT="$2"; shift 2 ;;
        --api-url)     API_URL="$2"; shift 2 ;;
        --api-pass)    API_PASS="$2"; shift 2 ;;
        --sim)         SIMULATE="true"; shift ;;
        --no-sim)      SIMULATE="false"; shift ;;
        --help)        usage ;;
        *)             err "Option inconnue: $1"; exit 1 ;;
    esac
done

# ══════════════════════════════════════════════════════════════════════════════
# VALIDATIONS
# ══════════════════════════════════════════════════════════════════════════════

if [[ -z "$HOST" ]]; then
    err "Adresse du RPi Zero W requise (-h)"
    exit 1
fi

if [[ ! -f "$INDEX_HTML" ]]; then
    err "index.html non trouvé: $INDEX_HTML"
    exit 1
fi

# ══════════════════════════════════════════════════════════════════════════════
# PRÉPARATION DU FICHIER
# ══════════════════════════════════════════════════════════════════════════════

log "═══════════════════════════════════════════════════════════════"
log "SecuBox Remote UI — Déploiement v$VERSION"
log "═══════════════════════════════════════════════════════════════"
log ""
log "Cible:    ${USER}@${HOST}:${PORT}"
log "API URL:  ${API_URL:-<non modifié>}"
log "Simulate: ${SIMULATE:-<non modifié>}"
log ""

# Créer une copie temporaire pour les patches
TEMP_HTML=$(mktemp)
cp "$INDEX_HTML" "$TEMP_HTML"

# Patch CFG.API_BASE si fourni
if [[ -n "$API_URL" ]]; then
    log "Patch API_BASE → $API_URL"
    sed -i "s|API_BASE: '[^']*'|API_BASE: '$API_URL'|" "$TEMP_HTML"
fi

# Patch CFG.LOGIN_PASS si fourni
if [[ -n "$API_PASS" ]]; then
    log "Patch LOGIN_PASS..."
    sed -i "s|LOGIN_PASS: '[^']*'|LOGIN_PASS: '$API_PASS'|" "$TEMP_HTML"
fi

# Patch CFG.SIMULATE si demandé
if [[ -n "$SIMULATE" ]]; then
    log "Patch SIMULATE → $SIMULATE"
    sed -i "s|SIMULATE: [a-z]*|SIMULATE: $SIMULATE|" "$TEMP_HTML"
fi

# ══════════════════════════════════════════════════════════════════════════════
# TEST CONNEXION SSH
# ══════════════════════════════════════════════════════════════════════════════

log "Test connexion SSH..."
if ! ssh -p "$PORT" -o ConnectTimeout=10 -o BatchMode=yes "${USER}@${HOST}" "echo ok" &>/dev/null; then
    err "Impossible de se connecter à ${USER}@${HOST}:${PORT}"
    err "Vérifiez que:"
    err "  - Le RPi est démarré et connecté au réseau"
    err "  - SSH est activé"
    err "  - Votre clé SSH est autorisée"
    rm -f "$TEMP_HTML"
    exit 1
fi
log "Connexion SSH OK"

# ══════════════════════════════════════════════════════════════════════════════
# DÉPLOIEMENT
# ══════════════════════════════════════════════════════════════════════════════

log "Copie du dashboard..."
scp -P "$PORT" "$TEMP_HTML" "${USER}@${HOST}:/tmp/index.html"

log "Installation..."
ssh -p "$PORT" "${USER}@${HOST}" << 'REMOTE_SCRIPT'
set -e

# Copier vers le répertoire web
sudo cp /tmp/index.html /var/www/secubox-round/index.html
sudo chown www-data:www-data /var/www/secubox-round/index.html
rm /tmp/index.html

# Recharger nginx
sudo systemctl reload nginx

echo "OK"
REMOTE_SCRIPT

# ══════════════════════════════════════════════════════════════════════════════
# PATCH NGINX PROXY (si API_URL fourni)
# ══════════════════════════════════════════════════════════════════════════════

if [[ -n "$API_URL" ]]; then
    # Extraire l'hôte et le port de l'URL
    API_HOST=$(echo "$API_URL" | sed -E 's|https?://([^:/]+).*|\1|')
    API_PORT=$(echo "$API_URL" | sed -E 's|https?://[^:]+:?([0-9]*).*|\1|')
    API_PORT=${API_PORT:-8000}

    log "Patch nginx proxy → ${API_HOST}:${API_PORT}"
    ssh -p "$PORT" "${USER}@${HOST}" << REMOTE_NGINX
set -e
sudo sed -i "s|proxy_pass http://[^;]*;|proxy_pass http://${API_HOST}:${API_PORT};|" /etc/nginx/sites-available/secubox-round
sudo nginx -t
sudo systemctl reload nginx
REMOTE_NGINX
fi

# ══════════════════════════════════════════════════════════════════════════════
# TEST HTTP
# ══════════════════════════════════════════════════════════════════════════════

log "Test HTTP..."
HTTP_CODE=$(ssh -p "$PORT" "${USER}@${HOST}" "curl -s -o /dev/null -w '%{http_code}' http://localhost:8080" 2>/dev/null || echo "000")

if [[ "$HTTP_CODE" == "200" ]]; then
    log "Test HTTP OK (200)"
else
    warn "Test HTTP retourne $HTTP_CODE (attendu 200)"
fi

# Nettoyage
rm -f "$TEMP_HTML"

# ══════════════════════════════════════════════════════════════════════════════
# RÉSUMÉ
# ══════════════════════════════════════════════════════════════════════════════

log ""
log "═══════════════════════════════════════════════════════════════"
log "Déploiement terminé !"
log "═══════════════════════════════════════════════════════════════"
log ""
log "Dashboard accessible sur le HyperPixel 2.1 Round"
log "Debug via: ssh ${USER}@${HOST} 'journalctl -u lightdm -f'"
log ""

if [[ "$SIMULATE" == "true" ]]; then
    warn "Mode SIMULATION activé — données fictives"
fi
