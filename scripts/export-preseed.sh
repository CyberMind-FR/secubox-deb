#!/bin/bash
# SecuBox Preseed Export Script
# Exports current system configuration to a preseed archive
# Usage: ./export-preseed.sh [output.tar.gz]

set -e

OUTPUT="${1:-secubox-preseed.tar.gz}"
PRESEED_DIR=$(mktemp -d)
trap "rm -rf ${PRESEED_DIR}" EXIT

echo "=== SecuBox Preseed Export ==="
echo "Exporting configuration to: ${OUTPUT}"

mkdir -p "${PRESEED_DIR}"/{etc,network,users,services,packages}

# ============================================
# 1. SecuBox Configuration
# ============================================
echo "[1/7] Exporting SecuBox configuration..."

if [ -d /etc/secubox ]; then
    cp -a /etc/secubox "${PRESEED_DIR}/etc/"
fi

# Export specific config files
for conf in /etc/hostname /etc/hosts /etc/timezone /etc/locale.gen; do
    [ -f "$conf" ] && cp "$conf" "${PRESEED_DIR}/etc/"
done

# ============================================
# 2. Network Configuration
# ============================================
echo "[2/7] Exporting network configuration..."

# Netplan
if [ -d /etc/netplan ]; then
    cp -a /etc/netplan "${PRESEED_DIR}/network/"
fi

# Network interfaces (legacy)
[ -f /etc/network/interfaces ] && cp /etc/network/interfaces "${PRESEED_DIR}/network/"

# WireGuard configs
if [ -d /etc/wireguard ]; then
    mkdir -p "${PRESEED_DIR}/network/wireguard"
    cp /etc/wireguard/*.conf "${PRESEED_DIR}/network/wireguard/" 2>/dev/null || true
fi

# DNS resolv.conf
[ -f /etc/resolv.conf ] && cp /etc/resolv.conf "${PRESEED_DIR}/network/"

# ============================================
# 3. User Accounts
# ============================================
echo "[3/7] Exporting user accounts..."

# Export shadow entries for secubox users (not system accounts)
awk -F: '$3 >= 1000 && $3 < 65000 {print}' /etc/passwd > "${PRESEED_DIR}/users/passwd"
awk -F: '$3 >= 1000 && $3 < 65000 {print $1}' /etc/passwd | while read user; do
    grep "^${user}:" /etc/shadow >> "${PRESEED_DIR}/users/shadow" 2>/dev/null || true
    grep "^${user}:" /etc/group >> "${PRESEED_DIR}/users/group" 2>/dev/null || true
done

# Root password hash (optional - comment out for security)
grep "^root:" /etc/shadow > "${PRESEED_DIR}/users/root-shadow" 2>/dev/null || true

# SSH authorized keys
for home in /root /home/*; do
    [ -d "$home" ] || continue
    user=$(basename "$home")
    if [ -f "${home}/.ssh/authorized_keys" ]; then
        mkdir -p "${PRESEED_DIR}/users/ssh/${user}"
        cp "${home}/.ssh/authorized_keys" "${PRESEED_DIR}/users/ssh/${user}/"
    fi
done

# ============================================
# 4. Service Configurations
# ============================================
echo "[4/7] Exporting service configurations..."

# nginx
[ -d /etc/nginx/sites-enabled ] && cp -a /etc/nginx/sites-enabled "${PRESEED_DIR}/services/nginx-sites"
[ -d /etc/nginx/conf.d ] && cp -a /etc/nginx/conf.d "${PRESEED_DIR}/services/nginx-conf"

# HAProxy
[ -f /etc/haproxy/haproxy.cfg ] && cp /etc/haproxy/haproxy.cfg "${PRESEED_DIR}/services/"

# CrowdSec
[ -d /etc/crowdsec ] && cp -a /etc/crowdsec "${PRESEED_DIR}/services/"

# nftables
[ -f /etc/nftables.conf ] && cp /etc/nftables.conf "${PRESEED_DIR}/services/"

# Postfix/Dovecot (mail)
[ -f /etc/postfix/main.cf ] && cp /etc/postfix/main.cf "${PRESEED_DIR}/services/"
[ -f /etc/dovecot/dovecot.conf ] && cp /etc/dovecot/dovecot.conf "${PRESEED_DIR}/services/"

# ============================================
# 5. SSL Certificates
# ============================================
echo "[5/7] Exporting SSL certificates..."

mkdir -p "${PRESEED_DIR}/ssl"

# Let's Encrypt / ACME
if [ -d /etc/letsencrypt ]; then
    cp -a /etc/letsencrypt "${PRESEED_DIR}/ssl/"
fi

# Custom certificates
if [ -d /etc/ssl/secubox ]; then
    cp -a /etc/ssl/secubox "${PRESEED_DIR}/ssl/"
fi

# ============================================
# 6. Installed Packages List
# ============================================
echo "[6/7] Exporting package list..."

dpkg --get-selections | grep -E "^secubox-" > "${PRESEED_DIR}/packages/secubox-packages.list"
apt-mark showmanual > "${PRESEED_DIR}/packages/manual-packages.list"

# ============================================
# 7. Custom Data
# ============================================
echo "[7/7] Exporting custom data..."

# Menu customizations
[ -d /etc/secubox/menu.d ] && cp -a /etc/secubox/menu.d "${PRESEED_DIR}/etc/"

# Create metadata
cat > "${PRESEED_DIR}/preseed.meta" << EOF
# SecuBox Preseed Metadata
export_date=$(date -Iseconds)
export_hostname=$(hostname)
export_version=$(cat /etc/secubox/version 2>/dev/null || echo "unknown")
secubox_packages=$(wc -l < "${PRESEED_DIR}/packages/secubox-packages.list")
EOF

# ============================================
# Create Archive
# ============================================
echo ""
echo "Creating preseed archive..."

tar -czf "${OUTPUT}" -C "${PRESEED_DIR}" .

echo ""
echo "=== Export Complete ==="
echo "Preseed archive: ${OUTPUT}"
echo "Size: $(du -h "${OUTPUT}" | cut -f1)"
echo ""
echo "Contents:"
tar -tzf "${OUTPUT}" | head -20
echo "..."
echo ""
echo "To use with live USB build:"
echo "  sudo bash image/build-live-usb.sh --preseed ${OUTPUT}"
