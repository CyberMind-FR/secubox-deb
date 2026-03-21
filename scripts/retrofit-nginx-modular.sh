#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  scripts/retrofit-nginx-modular.sh
#
#  Retrofit existing secubox-* packages with modular nginx config
#  Each module gets its own /etc/nginx/secubox.d/<module>.conf
# ══════════════════════════════════════════════════════════════════
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
NGINX_SNIPPETS="$REPO/common/nginx/modules.d"

echo "🔧 Retrofitting packages with modular nginx..."
echo ""

for PKG_DIR in "$REPO"/packages/secubox-*; do
    [[ ! -d "$PKG_DIR" ]] && continue

    PKG=$(basename "$PKG_DIR")
    NAME="${PKG#secubox-}"

    # Skip if no debian dir
    [[ ! -d "$PKG_DIR/debian" ]] && continue

    echo "📦 Processing $PKG..."

    # ── Create nginx directory and snippet ──
    mkdir -p "$PKG_DIR/nginx"
    if [[ -f "$NGINX_SNIPPETS/${NAME}.conf" ]]; then
        cp "$NGINX_SNIPPETS/${NAME}.conf" "$PKG_DIR/nginx/"
    else
        cat > "$PKG_DIR/nginx/${NAME}.conf" <<EOF
# /etc/nginx/secubox.d/${NAME}.conf
# Installed by ${PKG} — auto-registered on install
location /api/v1/${NAME}/ {
    proxy_pass http://unix:/run/secubox/${NAME}.sock:/;
    include /etc/nginx/snippets/secubox-proxy.conf;
}
EOF
    fi

    # ── Update debian/rules ──
    RULES="$PKG_DIR/debian/rules"
    if [[ -f "$RULES" ]] && ! grep -q "nginx/secubox.d" "$RULES"; then
        # Add nginx install line
        if grep -q "override_dh_auto_install:" "$RULES"; then
            echo "	# Modular nginx config" >> "$RULES"
            echo "	install -d debian/${PKG}/etc/nginx/secubox.d" >> "$RULES"
            echo "	[ -f nginx/${NAME}.conf ] && cp nginx/${NAME}.conf debian/${PKG}/etc/nginx/secubox.d/ || true" >> "$RULES"
        fi
        echo "   ✓ debian/rules updated"
    fi

    # ── Update debian/postinst ──
    POSTINST="$PKG_DIR/debian/postinst"
    if [[ -f "$POSTINST" ]] && ! grep -q "nginx/secubox.d" "$POSTINST"; then
        # Add secubox.d directory creation before nginx reload
        sed -i 's|systemctl reload nginx|install -d -m 755 /etc/nginx/secubox.d\n    systemctl reload nginx|' "$POSTINST"
        echo "   ✓ debian/postinst updated"
    fi

    # ── Update debian/prerm ──
    PRERM="$PKG_DIR/debian/prerm"
    if [[ -f "$PRERM" ]] && ! grep -q "secubox.d/${NAME}.conf" "$PRERM"; then
        # Add nginx snippet removal
        sed -i "/remove|upgrade/a\\    rm -f /etc/nginx/secubox.d/${NAME}.conf" "$PRERM"
        # Add nginx reload if not present
        if ! grep -q "reload nginx" "$PRERM"; then
            sed -i "/systemctl disable/a\\    systemctl reload nginx 2>/dev/null || true" "$PRERM"
        fi
        echo "   ✓ debian/prerm updated"
    fi

    echo ""
done

echo "✅ Done! Verify changes:"
echo "   git diff packages/*/debian/"
echo "   git diff packages/*/nginx/"
