#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  scripts/new-package.sh — Scaffold un nouveau paquet secubox-*
#
#  Usage :
#    bash scripts/new-package.sh mymodule "My Module Description"
# ══════════════════════════════════════════════════════════════════
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"

NAME="${1:-}"
DESC="${2:-SecuBox module}"

[[ -z "$NAME" ]] && { echo "Usage: $0 <name> [description]"; exit 1; }

PKG="secubox-${NAME}"
PKG_DIR="$REPO/packages/$PKG"

[[ -d "$PKG_DIR" ]] && { echo "❌ $PKG existe déjà"; exit 1; }

echo "📦 Création $PKG..."
mkdir -p "$PKG_DIR"/{debian,api/routers,www}

# ── api/main.py ──
cat > "$PKG_DIR/api/main.py" <<PYEOF
"""${PKG} — FastAPI application."""
from fastapi import FastAPI
from secubox_core.auth import router as auth_router
from .routers import status

app = FastAPI(title="${PKG}", root_path="/api/v1/${NAME}")
app.include_router(auth_router, prefix="/auth")
app.include_router(status.router, tags=["status"])

@app.get("/health")
async def health():
    return {"status": "ok", "module": "${NAME}"}
PYEOF

# ── api/routers/status.py ──
cat > "$PKG_DIR/api/routers/status.py" <<PYEOF
"""${PKG} status router."""
from fastapi import APIRouter, Depends
from secubox_core.auth import require_jwt
from secubox_core.logger import get_logger

router = APIRouter()
log = get_logger("${NAME}")

@router.get("/status")
async def status(user=Depends(require_jwt)):
    return {"running": True, "module": "${NAME}"}
PYEOF

cat > "$PKG_DIR/api/__init__.py" <<< ""
cat > "$PKG_DIR/api/routers/__init__.py" <<< ""

# ── debian/control ──
cat > "$PKG_DIR/debian/control" <<CTRL
Source: ${PKG}
Section: net
Priority: optional
Maintainer: Gandalf / CyberMind <gk@cybermind.fr>
Build-Depends: debhelper-compat (= 13)
Standards-Version: 4.6.2

Package: ${PKG}
Architecture: all
Depends: \${misc:Depends}, secubox-core (>= 1.0),
 python3-uvicorn
Description: ${DESC}
 Port Debian bookworm du module luci-app-${NAME} de SecuBox OpenWrt.
CTRL

# ── debian/rules ──
cat > "$PKG_DIR/debian/rules" <<'RULES'
#!/usr/bin/make -f
%:
	dh $@
RULES
chmod +x "$PKG_DIR/debian/rules"

# ── debian/compat ──
echo "13" > "$PKG_DIR/debian/compat"

# ── debian/changelog ──
cat > "$PKG_DIR/debian/changelog" <<CHLOG
${PKG} (1.0.0-1~bookworm1) bookworm; urgency=medium

  * Initial release.

 -- Gandalf / CyberMind <gk@cybermind.fr>  $(date -R)
CHLOG

# ── debian/postinst ──
cat > "$PKG_DIR/debian/postinst" <<POSTINST
#!/bin/bash
set -e
case "\$1" in
  configure)
    id -u secubox >/dev/null 2>&1 || \
      adduser --system --group --no-create-home --home /var/lib/secubox secubox
    install -d -o secubox -g secubox -m 750 /run/secubox
    install -d -o secubox -g secubox -m 750 /var/lib/secubox
    install -d -m 755 /usr/lib/secubox/${NAME}
    cp -r /usr/share/${PKG}/api /usr/lib/secubox/${NAME}/
    systemctl daemon-reload
    systemctl enable ${PKG}.service
    systemctl start  ${PKG}.service || true
    systemctl reload nginx 2>/dev/null || true
    ;;
esac
#DEBHELPER#
POSTINST
chmod +x "$PKG_DIR/debian/postinst"

# ── debian/prerm ──
cat > "$PKG_DIR/debian/prerm" <<PRERM
#!/bin/bash
set -e
case "\$1" in
  remove|upgrade)
    systemctl stop    ${PKG}.service 2>/dev/null || true
    systemctl disable ${PKG}.service 2>/dev/null || true
    ;;
esac
#DEBHELPER#
PRERM
chmod +x "$PKG_DIR/debian/prerm"

# ── systemd unit ──
cat > "$PKG_DIR/debian/${PKG}.service" <<SVC
[Unit]
Description=SecuBox ${NAME^} API
After=network.target secubox-core.service
Requires=secubox-core.service

[Service]
Type=simple
User=secubox
Group=secubox
WorkingDirectory=/usr/lib/secubox/${NAME}
ExecStart=/usr/bin/uvicorn api.main:app --uds /run/secubox/${NAME}.sock --log-level warning
ExecStartPost=/bin/chmod 660 /run/secubox/${NAME}.sock
Restart=on-failure
RestartSec=5
PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/run/secubox /var/lib/secubox /etc/secubox

[Install]
WantedBy=multi-user.target
SVC

# ── debian/install ──
cat > "$PKG_DIR/debian/${PKG}.install" <<INST
api usr/share/${PKG}/
www usr/share/secubox/
INST

echo "✅ Package $PKG créé dans $PKG_DIR"
echo "   Prochaines étapes :"
echo "   1. Implémenter api/routers/*.py"
echo "   2. Porter le frontend : bash scripts/port-frontend.sh ${NAME}"
echo "   3. Build : cd $PKG_DIR && dpkg-buildpackage -a arm64 -us -uc -b"
