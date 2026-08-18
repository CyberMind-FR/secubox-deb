#!/bin/bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox Nginx Auto-Sync — Link ALL webui directories to nginx routes
set -uo pipefail

WEBUI_DIR="/usr/share/secubox/www"
SOCKET_DIR="/run/secubox"
NGINX_CONF="/etc/nginx/sites-enabled/webui.conf"
SNIPPET="/etc/nginx/snippets/secubox-proxy.conf"
SKIP_MODULES="shared|js|prototypes|luci-static"

echo "[SecuBox] Nginx Auto-Sync — ALL modules"

# Backup
backup="$NGINX_CONF.bak.$(date +%s)"
cp "$NGINX_CONF" "$backup"

# Get existing routes
existing=$(grep -oP "location /api/v1/\K[^/]+" "$NGINX_CONF" 2>/dev/null | sort -u || true)

# Get webui modules
modules=$(ls -d "$WEBUI_DIR"/*/ | xargs -I{} basename {} | grep -vE "^($SKIP_MODULES)$" | sort)

# Temp file for new config
tmpfile=$(mktemp)
head -n -1 "$NGINX_CONF" > "$tmpfile"

added=0
for m in $modules; do
    if echo "$existing" | grep -qx "$m"; then
        continue
    fi
    echo "[+] $m"
    cat >> "$tmpfile" << BLOCK

    # $m static
    location /$m/ {
        alias $WEBUI_DIR/$m/;
        index index.html;
        try_files \$uri \$uri/ /$m/index.html;
    }
    # $m API
    location /api/v1/$m/ {
        proxy_pass http://unix:$SOCKET_DIR/$m.sock:/;
        include $SNIPPET;
        proxy_intercept_errors on;
    }
BLOCK
    ((added++)) || true
done

echo "}" >> "$tmpfile"

if [ $added -eq 0 ]; then
    echo "[i] All modules already configured"
    rm "$tmpfile"
    exit 0
fi

mv "$tmpfile" "$NGINX_CONF"

echo "[i] Added $added routes, testing..."
if nginx -t 2>/dev/null; then
    nginx -s reload 2>/dev/null
    echo "[✓] Done! $added new routes active"
else
    echo "[✗] Error, restoring..."
    cp "$backup" "$NGINX_CONF"
    nginx -s reload 2>/dev/null
    exit 1
fi
