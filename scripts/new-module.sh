#!/bin/bash
# SecuBox Module Scaffold Script
# Usage: ./new-module.sh <module-name> "<description>" [category] [icon] [order]

set -e
cd "$(dirname "$0")/.."

NAME="$1"
DESC="${2:-SecuBox $NAME module}"
CATEGORY="${3:-apps}"
ICON="${4:-📦}"
ORDER="${5:-500}"

if [ -z "$NAME" ]; then
    echo "Usage: $0 <module-name> [description] [category] [icon] [order]"
    echo "Categories: dashboard, security, network, monitoring, publishing, apps"
    exit 1
fi

PKG="packages/secubox-$NAME"
if [ -d "$PKG" ]; then
    echo "Error: $PKG already exists"
    exit 1
fi

NAME_UPPER=$(echo "$NAME" | sed 's/.*/\u&/')
echo "Creating module: $NAME ($DESC)"

# Create directory structure
mkdir -p "$PKG"/{api,www/$NAME,menu.d,debian}

# API main.py
cat > "$PKG/api/__init__.py" << 'EOF'
"""SecuBox API Module"""
EOF

cat > "$PKG/api/main.py" << EOF
"""SecuBox $NAME_UPPER API"""
from fastapi import FastAPI, Depends
from secubox_core.auth import require_jwt
from secubox_core.config import get_config

app = FastAPI(title="SecuBox $NAME_UPPER")
config = get_config("$NAME")

@app.get("/status")
async def status():
    """Public status endpoint"""
    return {
        "module": "$NAME",
        "status": "ok",
        "version": "1.0.0"
    }

@app.get("/info", dependencies=[Depends(require_jwt)])
async def info():
    """Protected info endpoint"""
    return {"config": dict(config)}
EOF

# Frontend index.html
cat > "$PKG/www/$NAME/index.html" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecuBox - $NAME_UPPER</title>
    <style>
        :root { --bg-dark: #0d1117; --bg-card: #161b22; --bg-sidebar: #0d1117; --border: #30363d; --text: #c9d1d9; --text-dim: #8b949e; --primary: #58a6ff; --cyan: #00d4ff; --green: #3fb950; --red: #f85149; --yellow: #d29922; --purple: #a371f7; }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, sans-serif; background: var(--bg-dark); color: var(--text); display: flex; min-height: 100vh; }
        .sidebar { width: 220px; background: var(--bg-sidebar); border-right: 1px solid var(--border); position: fixed; height: 100vh; overflow-y: auto; }
        .sidebar-header { padding: 1rem; border-bottom: 1px solid var(--border); }
        .logo { font-weight: bold; font-size: 1.2rem; }
        .logo span:nth-child(1) { color: var(--cyan); } .logo span:nth-child(2) { color: var(--red); } .logo span:nth-child(3) { color: var(--green); } .logo span:nth-child(4) { color: var(--yellow); }
        .nav-section { padding: 0.5rem 0; }
        .nav-section-title { padding: 0.5rem 1rem; font-size: 0.75rem; color: var(--text-dim); text-transform: uppercase; }
        .nav-item { display: flex; align-items: center; gap: 0.75rem; padding: 0.6rem 1rem; color: var(--text-dim); text-decoration: none; font-size: 0.9rem; border-left: 3px solid transparent; }
        .nav-item:hover { background: rgba(255,255,255,0.05); color: var(--text); }
        .nav-item.active { background: rgba(88,166,255,0.1); color: var(--primary); border-left-color: var(--primary); }
        .nav-item .icon { width: 20px; text-align: center; }
        .main { flex: 1; margin-left: 220px; padding: 1.5rem; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; }
        .header h1 { font-size: 1.5rem; }
        .btn { padding: 0.5rem 1rem; border-radius: 6px; border: 1px solid var(--border); background: var(--bg-card); color: var(--text); cursor: pointer; }
        .btn:hover { background: var(--bg-dark); }
        .btn.primary { background: rgba(88,166,255,0.1); border-color: var(--primary); color: var(--primary); }
        .card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; margin-bottom: 1.5rem; }
        .card h2 { font-size: 1rem; margin-bottom: 1rem; }
        .stat-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; text-align: center; }
        .stat-card .value { font-size: 2rem; font-weight: bold; color: var(--purple); }
        .stat-card .label { font-size: 0.75rem; color: var(--text-dim); }
    </style>
</head>
<body>
    <nav class="sidebar" id="sidebar"></nav>
    <script src="/shared/sidebar.js"></script>
    <main class="main">
        <header class="header">
            <h1>$NAME_UPPER</h1>
            <button class="btn" onclick="refresh()">Refresh</button>
        </header>
        <div class="card">
            <h2>Status</h2>
            <p id="status">Loading...</p>
        </div>
        <script>
            const API = '/api/v1/$NAME';
            const token = () => localStorage.getItem('sbx_token');
            const headers = () => ({ 'Content-Type': 'application/json', ...(token() ? { 'Authorization': 'Bearer ' + token() } : {}) });

            async function api(path, opts = {}) {
                try {
                    const res = await fetch(API + path, { ...opts, headers: headers() });
                    if (res.status === 401) { window.location = '/login/'; return {}; }
                    return res.json();
                } catch { return {}; }
            }

            async function loadStatus() {
                const d = await api('/status');
                document.getElementById('status').textContent = JSON.stringify(d, null, 2);
            }

            function refresh() { loadStatus(); }
            refresh();
        </script>
    </main>
</body>
</html>
EOF

# Menu definition
cat > "$PKG/menu.d/${ORDER}-$NAME.json" << EOF
{
  "id": "$NAME",
  "name": "$NAME_UPPER",
  "category": "$CATEGORY",
  "icon": "$ICON",
  "path": "/$NAME/",
  "order": $ORDER,
  "description": "$DESC"
}
EOF

# Debian control
cat > "$PKG/debian/control" << EOF
Source: secubox-$NAME
Section: admin
Priority: optional
Maintainer: SecuBox <dev@secubox.local>
Build-Depends: debhelper-compat (= 13)
Standards-Version: 4.6.2

Package: secubox-$NAME
Architecture: all
Depends: \${misc:Depends}, secubox-core (>= 1.0.0)
Description: SecuBox $NAME_UPPER Module
 $DESC
EOF

# Debian changelog
cat > "$PKG/debian/changelog" << EOF
secubox-$NAME (1.0.0-1~bookworm1) bookworm; urgency=medium

  * Initial release

 -- SecuBox <dev@secubox.local>  $(date -R)
EOF

# Debian compat
echo "13" > "$PKG/debian/compat"

# Debian rules
cat > "$PKG/debian/rules" << 'EOF'
#!/usr/bin/make -f
%:
	dh $@

override_dh_auto_install:
	install -d debian/secubox-MODULE/usr/lib/secubox/MODULE
	cp -r api debian/secubox-MODULE/usr/lib/secubox/MODULE/
	install -d debian/secubox-MODULE/usr/share/secubox/www/MODULE
	cp -r www/MODULE/. debian/secubox-MODULE/usr/share/secubox/www/MODULE/
	install -d debian/secubox-MODULE/usr/share/secubox/menu.d
	[ -d menu.d ] && cp -r menu.d/. debian/secubox-MODULE/usr/share/secubox/menu.d/ || true
	install -d debian/secubox-MODULE/lib/systemd/system
	install -m 644 debian/secubox-MODULE.service debian/secubox-MODULE/lib/systemd/system/
EOF
sed -i "s/MODULE/$NAME/g" "$PKG/debian/rules"
chmod +x "$PKG/debian/rules"

# Debian postinst
cat > "$PKG/debian/postinst" << EOF
#!/bin/sh
set -e
if [ "\$1" = "configure" ]; then
    systemctl daemon-reload
    systemctl enable secubox-$NAME.service || true
    systemctl start secubox-$NAME.service || true
fi
#DEBHELPER#
exit 0
EOF
chmod +x "$PKG/debian/postinst"

# Debian prerm
cat > "$PKG/debian/prerm" << EOF
#!/bin/sh
set -e
if [ "\$1" = "remove" ]; then
    systemctl stop secubox-$NAME.service || true
    systemctl disable secubox-$NAME.service || true
fi
#DEBHELPER#
exit 0
EOF
chmod +x "$PKG/debian/prerm"

# Systemd service
cat > "$PKG/debian/secubox-$NAME.service" << EOF
[Unit]
Description=SecuBox $NAME_UPPER API
After=network.target secubox-core.service
Requires=secubox-core.service

[Service]
Type=simple
User=secubox
Group=secubox
WorkingDirectory=/usr/lib/secubox/$NAME
ExecStart=/usr/bin/python3 -m uvicorn api.main:app --uds /run/secubox/$NAME.sock --log-level warning
Restart=on-failure
RestartSec=5
UMask=0000
PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/run/secubox /var/lib/secubox /etc/secubox

[Install]
WantedBy=multi-user.target
EOF

echo ""
echo "Created: $PKG"
echo ""
echo "Next steps:"
echo "1. Implement API endpoints in $PKG/api/main.py"
echo "2. Customize frontend in $PKG/www/$NAME/index.html"
echo "3. Build: cd $PKG && dpkg-buildpackage -us -uc -b"
echo "4. Add nginx location to common/nginx/secubox.conf:"
echo ""
echo "    location /api/v1/$NAME/ {"
echo "        proxy_pass http://unix:/run/secubox/$NAME.sock:/;"
echo "        include /etc/nginx/snippets/secubox-proxy.conf;"
echo "    }"
