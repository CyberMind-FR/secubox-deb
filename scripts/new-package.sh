#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  scripts/new-package.sh — Scaffold un nouveau paquet secubox-*
#
#  Usage :
#    bash scripts/new-package.sh mymodule "My Module Description"
#
#  Features:
#    - FastAPI app with auth
#    - Debian packaging (control, rules, postinst, prerm)
#    - Systemd service (Unix socket)
#    - Modular nginx config (auto-register in /etc/nginx/secubox.d/)
#    - Menu registration (menu.d)
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
mkdir -p "$PKG_DIR"/{debian,api/routers,www/${NAME},nginx}

# ══════════════════════════════════════════════════════════════════
# API FILES
# ══════════════════════════════════════════════════════════════════

# ── api/main.py ──
cat > "$PKG_DIR/api/main.py" <<PYEOF
"""${PKG} — FastAPI application."""
from fastapi import FastAPI, APIRouter, Depends
from secubox_core.auth import router as auth_router, require_jwt
from secubox_core.logger import get_logger

app = FastAPI(title="${PKG}", version="1.0.0", root_path="/api/v1/${NAME}")
app.include_router(auth_router, prefix="/auth")
router = APIRouter()
log = get_logger("${NAME}")


@router.get("/status")
async def status():
    """Module status (public)."""
    return {"module": "${NAME}", "version": "1.0.0", "running": True}


@router.get("/info")
async def info(user=Depends(require_jwt)):
    """Module info (protected)."""
    return {"module": "${NAME}", "description": "${DESC}"}


@router.get("/health")
async def health():
    return {"status": "ok", "module": "${NAME}"}


app.include_router(router)
PYEOF

cat > "$PKG_DIR/api/__init__.py" <<< ""
cat > "$PKG_DIR/api/routers/__init__.py" <<< ""

# ══════════════════════════════════════════════════════════════════
# NGINX MODULAR CONFIG
# ══════════════════════════════════════════════════════════════════

cat > "$PKG_DIR/nginx/${NAME}.conf" <<NGINX
# /etc/nginx/secubox.d/${NAME}.conf
# Installed by ${PKG} — auto-registered on install, removed on purge
location /api/v1/${NAME}/ {
    proxy_pass http://unix:/run/secubox/${NAME}.sock:/;
    include /etc/nginx/snippets/secubox-proxy.conf;
}
NGINX

# ══════════════════════════════════════════════════════════════════
# FRONTEND PLACEHOLDER
# ══════════════════════════════════════════════════════════════════

cat > "$PKG_DIR/www/${NAME}/index.html" <<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecuBox - ${NAME^}</title>
    <link rel="stylesheet" href="/shared/sidebar.css">
    <style>
        :root { --bg-dark: #0d1117; --bg-card: #161b22; --border: #30363d; --text: #c9d1d9; --text-dim: #8b949e; --cyan: #00d4ff; }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, sans-serif; background: var(--bg-dark); color: var(--text); display: flex; min-height: 100vh; }
        .main { flex: 1; margin-left: 220px; padding: 1.5rem; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; }
        .header h1 { font-size: 1.5rem; }
        .btn { padding: 0.5rem 1rem; border-radius: 6px; border: 1px solid var(--border); background: var(--bg-card); color: var(--text); cursor: pointer; }
        .btn:hover { background: var(--bg-dark); }
        .card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; margin-bottom: 1.5rem; }
        .card h2 { font-size: 1rem; margin-bottom: 1rem; color: var(--cyan); }
    </style>
</head>
<body>
    <nav class="sidebar" id="sidebar"></nav>
    <script src="/shared/sidebar.js"></script>
    <main class="main">
        <header class="header">
            <h1>${NAME^}</h1>
            <button class="btn" onclick="refresh()">Refresh</button>
        </header>
        <div class="card">
            <h2>Module Status</h2>
            <p id="status">Loading...</p>
        </div>
    </main>
    <script>
        const API = '/api/v1/${NAME}';
        async function refresh() {
            try {
                const res = await fetch(API + '/status', { credentials: 'include' });
                const data = await res.json();
                document.getElementById('status').textContent = JSON.stringify(data, null, 2);
            } catch(e) {
                document.getElementById('status').textContent = 'Error: ' + e.message;
            }
        }
        refresh();
    </script>
</body>
</html>
HTML

# ══════════════════════════════════════════════════════════════════
# DEBIAN PACKAGING
# ══════════════════════════════════════════════════════════════════

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
Depends: \${misc:Depends}, secubox-core (>= 1.0), python3-uvicorn
Description: ${DESC}
 Port Debian bookworm du module luci-app-${NAME} de SecuBox OpenWrt.
 Provides FastAPI backend on /api/v1/${NAME}/ via Unix socket.
CTRL

# ── debian/rules ──
cat > "$PKG_DIR/debian/rules" <<RULES
#!/usr/bin/make -f
%:
	dh \$@

override_dh_auto_install:
	# API files
	install -d debian/${PKG}/usr/lib/secubox/${NAME}/
	cp -r api debian/${PKG}/usr/lib/secubox/${NAME}/
	# Static www files
	install -d debian/${PKG}/usr/share/secubox/www
	[ -d www ] && cp -r www/. debian/${PKG}/usr/share/secubox/www/ || true
	# Menu definitions
	install -d debian/${PKG}/usr/share/secubox/menu.d
	[ -d menu.d ] && cp -r menu.d/. debian/${PKG}/usr/share/secubox/menu.d/ || true
	# Modular nginx config
	install -d debian/${PKG}/etc/nginx/secubox.d
	[ -f nginx/${NAME}.conf ] && cp nginx/${NAME}.conf debian/${PKG}/etc/nginx/secubox.d/ || true
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
cat > "$PKG_DIR/debian/postinst" <<'POSTINST'
#!/bin/bash
set -e
case "$1" in
  configure)
    # Ensure secubox user exists
    id -u secubox >/dev/null 2>&1 || \
      adduser --system --group --no-create-home \
        --home /var/lib/secubox --shell /usr/sbin/nologin secubox
    # Create runtime directories
    install -d -o secubox -g secubox -m 750 /run/secubox
    install -d -o secubox -g secubox -m 750 /var/lib/secubox
    # Ensure nginx secubox.d directory exists
    install -d -m 755 /etc/nginx/secubox.d
    # Enable and start service
    systemctl daemon-reload
    systemctl enable PKGNAME.service
    systemctl start  PKGNAME.service || true
    # Reload nginx to pick up new location
    systemctl reload nginx 2>/dev/null || true
    ;;
esac
#DEBHELPER#
POSTINST
sed -i "s/PKGNAME/${PKG}/g" "$PKG_DIR/debian/postinst"
chmod +x "$PKG_DIR/debian/postinst"

# ── debian/prerm ──
cat > "$PKG_DIR/debian/prerm" <<'PRERM'
#!/bin/bash
set -e
case "$1" in
  remove|upgrade)
    # Remove nginx location config
    rm -f /etc/nginx/secubox.d/MODNAME.conf
    # Stop and disable service
    systemctl stop    PKGNAME.service 2>/dev/null || true
    systemctl disable PKGNAME.service 2>/dev/null || true
    # Reload nginx to remove location
    systemctl reload nginx 2>/dev/null || true
    ;;
esac
#DEBHELPER#
PRERM
sed -i "s/PKGNAME/${PKG}/g; s/MODNAME/${NAME}/g" "$PKG_DIR/debian/prerm"
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

echo ""
echo "✅ Package $PKG créé dans $PKG_DIR"
echo ""
echo "   Structure:"
echo "   ├── api/main.py           # FastAPI app"
echo "   ├── www/${NAME}/index.html   # Frontend"
echo "   ├── nginx/${NAME}.conf       # Nginx location (auto-register)"
echo "   └── debian/               # Packaging"
echo ""
echo "   Prochaines étapes:"
echo "   1. Implémenter l'API dans api/main.py"
echo "   2. Porter le frontend depuis secubox-openwrt (si applicable)"
echo "   3. Build: cd $PKG_DIR && dpkg-buildpackage -us -uc -b"
echo "   4. Deploy: scp ../${PKG}*.deb root@vm:/tmp/ && ssh root@vm dpkg -i /tmp/${PKG}*.deb"
