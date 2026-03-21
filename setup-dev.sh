#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  SecuBox-DEB — setup-dev.sh
#  Installation de l'environnement de développement local
# ══════════════════════════════════════════════════════════════════
set -euo pipefail
REPO="$(cd "$(dirname "$0")" && pwd)"

C='\033[0;36m'; G='\033[0;32m'; Y='\033[0;33m'; R='\033[0;31m'; N='\033[0m'; B='\033[1m'
log()  { echo -e "${C}▶ $*${N}"; }
ok()   { echo -e "${G}  ✓ $*${N}"; }
warn() { echo -e "${Y}  ⚠ $*${N}"; }

echo -e "${Y}${B}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║  SecuBox-DEB — Dev Environment Setup     ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${N}"

# ── Python ────────────────────────────────────────────────────────
log "Python 3.10+"
PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")
if [ "${PY_MINOR}" -lt 10 ]; then
  echo -e "${R}❌ Python 3.10+ requis (trouvé: $PY_VER)${N}"
  exit 1
fi
ok "Python $PY_VER"

# ── Virtualenv ────────────────────────────────────────────────────
log "Virtualenv .venv"
if [ ! -d "$REPO/.venv" ]; then
  python3 -m venv "$REPO/.venv"
fi
source "$REPO/.venv/bin/activate"
ok ".venv activé"

# ── Pip packages ──────────────────────────────────────────────────
log "Packages Python"
pip install --quiet --upgrade pip
pip install --quiet \
  fastapi "uvicorn[standard]" \
  "python-jose[cryptography]" \
  httpx jinja2 psutil \
  pyroute2 aiosqlite \
  tomli \
  black ruff pytest pytest-asyncio httpx
ok "Packages installés"

# ── PYTHONPATH ────────────────────────────────────────────────────
log "Configuration PYTHONPATH"
if ! grep -q "PYTHONPATH" "$REPO/.venv/bin/activate" 2>/dev/null; then
  echo "export PYTHONPATH=\"$REPO/common:\$PYTHONPATH\"" >> "$REPO/.venv/bin/activate"
fi
export PYTHONPATH="$REPO/common:${PYTHONPATH:-}"
ok "PYTHONPATH → $REPO/common"

# ── Vérification imports ──────────────────────────────────────────
log "Test imports secubox_core"
python3 -c "
from secubox_core.auth import create_token, require_jwt
from secubox_core.config import get_config, get_board_info
from secubox_core.logger import get_logger
print('  ✓ secubox_core OK')
"

# ── Outils système ────────────────────────────────────────────────
log "Outils système"
for cmd in nft ip tc wg netplan; do
  if command -v $cmd &>/dev/null; then
    ok "$cmd disponible"
  else
    warn "$cmd absent (normal en dev, requis sur board)"
  fi
done

# ── .env ──────────────────────────────────────────────────────────
log "Fichier .env"
if [ ! -f "$REPO/.env" ]; then
  cat > "$REPO/.env" <<EOF
# SecuBox-DEB — Variables d'environnement de développement
export PYTHONPATH="$REPO/common:\$PYTHONPATH"
export SECUBOX_DEBUG=1
export SECUBOX_JWT_SECRET="dev-secret-not-for-production"
export ANTHROPIC_API_KEY=""
EOF
  ok ".env créé"
else
  ok ".env existant conservé"
fi

# ── Répertoires de dev ────────────────────────────────────────────
mkdir -p "$REPO/output"

# ── Résumé ────────────────────────────────────────────────────────
echo ""
echo -e "${Y}${B}══════════════════════════════════════════════${N}"
echo -e "${G}${B}  Setup terminé !${N}"
echo ""
echo -e "  Activer l'env : ${C}source .venv/bin/activate && source .env${N}"
echo ""
echo -e "  Lancer un module en dev :"
echo -e "  ${C}cd packages/secubox-crowdsec${N}"
echo -e "  ${C}uvicorn api.main:app --reload --host 127.0.0.1 --port 8001${N}"
echo ""
echo -e "  VSCode : ${C}Ctrl+Shift+B${N} → choisir une task"
echo -e "${Y}${B}══════════════════════════════════════════════${N}"
