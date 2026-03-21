#!/bin/bash
# Update debian packaging for modular nginx configuration
# Each module installs /etc/nginx/secubox.d/<module>.conf

BASEDIR="/home/reepost/CyberMindStudio/secubox-deb/secubox-deb"

modules="hub crowdsec netdata wireguard dpi netmodes nac auth qos mediaflow cdn vhost system waf portal dns haproxy droplet metablogizer publish streamlit streamforge mail webmail mail-lxc webmail-lxc users"

for mod in $modules; do
    PKG_DIR="$BASEDIR/packages/secubox-$mod"
    PKG_NAME="secubox-$mod"

    if [ ! -d "$PKG_DIR/debian" ]; then
        echo "SKIP: $mod (no debian dir)"
        continue
    fi

    # ── Update debian/rules ──
    RULES="$PKG_DIR/debian/rules"
    if [ -f "$RULES" ]; then
        # Check if nginx install already exists
        if ! grep -q "nginx/secubox.d" "$RULES"; then
            # Add nginx snippet installation before the last line
            sed -i '/^override_dh_auto_install:/,/^[a-z]/ {
                /\[ -d menu.d \]/ a\
	install -d debian/'"$PKG_NAME"'/etc/nginx/secubox.d\
	[ -f nginx/'"$mod"'.conf ] \&\& cp nginx/'"$mod"'.conf debian/'"$PKG_NAME"'/etc/nginx/secubox.d/ || true
            }' "$RULES"
            echo "OK: $mod - debian/rules updated"
        else
            echo "SKIP: $mod - debian/rules already has nginx"
        fi
    fi

    # ── Update debian/postinst ──
    POSTINST="$PKG_DIR/debian/postinst"
    if [ -f "$POSTINST" ]; then
        # Check if secubox.d mkdir already exists
        if ! grep -q "secubox.d" "$POSTINST"; then
            # Add before systemctl reload nginx
            sed -i 's|systemctl reload nginx|install -d -m 755 /etc/nginx/secubox.d\n    systemctl reload nginx|' "$POSTINST"
            echo "OK: $mod - debian/postinst updated"
        else
            echo "SKIP: $mod - debian/postinst already has secubox.d"
        fi
    fi

    # ── Update debian/prerm ──
    PRERM="$PKG_DIR/debian/prerm"
    if [ -f "$PRERM" ]; then
        # Check if nginx snippet removal already exists
        if ! grep -q "secubox.d/$mod.conf" "$PRERM"; then
            # Add snippet removal before systemctl stop
            sed -i "/systemctl stop/i\\    rm -f /etc/nginx/secubox.d/$mod.conf" "$PRERM"
            # Add nginx reload after systemctl stop
            if ! grep -q "reload nginx" "$PRERM"; then
                sed -i "/systemctl stop/a\\    systemctl reload nginx 2>/dev/null || true" "$PRERM"
            fi
            echo "OK: $mod - debian/prerm updated"
        else
            echo "SKIP: $mod - debian/prerm already handles nginx"
        fi
    fi
done

echo ""
echo "Done. Verify changes with: git diff packages/*/debian/"
