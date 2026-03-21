#!/bin/bash
# Update all module packages for modular nginx configuration
# Each module installs its own /etc/nginx/secubox.d/<module>.conf

BASEDIR="/home/reepost/CyberMindStudio/secubox-deb/secubox-deb"
NGINX_SNIPPETS="$BASEDIR/common/nginx/modules.d"

modules="hub crowdsec netdata wireguard dpi netmodes nac auth qos mediaflow cdn vhost system waf portal dns haproxy droplet metablogizer publish streamlit streamforge mail webmail mail-lxc webmail-lxc users"

for mod in $modules; do
    PKG_DIR="$BASEDIR/packages/secubox-$mod"

    if [ ! -d "$PKG_DIR" ]; then
        echo "SKIP: $mod (no package dir)"
        continue
    fi

    # Create nginx directory in package
    mkdir -p "$PKG_DIR/nginx"

    # Copy nginx snippet
    if [ -f "$NGINX_SNIPPETS/${mod}.conf" ]; then
        cp "$NGINX_SNIPPETS/${mod}.conf" "$PKG_DIR/nginx/"
        echo "OK: $mod - nginx snippet copied"
    else
        echo "WARN: $mod - no nginx snippet"
    fi
done

echo ""
echo "Done. Now update debian/rules and debian/postinst for each module."
