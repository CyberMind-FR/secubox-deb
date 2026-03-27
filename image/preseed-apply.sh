#!/bin/bash
# SecuBox Preseed Apply Script
# Applies preseed configuration on firstboot
# Runs from: /usr/lib/secubox/preseed-apply.sh

set -e

PRESEED_ARCHIVE="/usr/share/secubox/preseed.tar.gz"
PRESEED_DIR="/tmp/preseed-apply"
LOG="/var/log/secubox-preseed.log"
MARKER="/var/lib/secubox/.preseed-applied"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"
}

# Check if already applied
if [ -f "$MARKER" ]; then
    log "Preseed already applied, skipping"
    exit 0
fi

# Check if preseed exists
if [ ! -f "$PRESEED_ARCHIVE" ]; then
    log "No preseed archive found at ${PRESEED_ARCHIVE}"
    exit 0
fi

log "=== SecuBox Preseed Apply ==="
log "Extracting preseed archive..."

mkdir -p "$PRESEED_DIR"
tar -xzf "$PRESEED_ARCHIVE" -C "$PRESEED_DIR"

# Read metadata
if [ -f "${PRESEED_DIR}/preseed.meta" ]; then
    source "${PRESEED_DIR}/preseed.meta"
    log "Preseed from: ${export_hostname} (${export_date})"
fi

# ============================================
# 1. Apply SecuBox Configuration
# ============================================
log "[1/7] Applying SecuBox configuration..."

if [ -d "${PRESEED_DIR}/etc/secubox" ]; then
    mkdir -p /etc/secubox
    cp -a "${PRESEED_DIR}/etc/secubox/"* /etc/secubox/ 2>/dev/null || true
    log "  - SecuBox config restored"
fi

# Hostname
if [ -f "${PRESEED_DIR}/etc/hostname" ]; then
    cp "${PRESEED_DIR}/etc/hostname" /etc/hostname
    hostname -F /etc/hostname
    log "  - Hostname set to: $(cat /etc/hostname)"
fi

# Hosts file
[ -f "${PRESEED_DIR}/etc/hosts" ] && cp "${PRESEED_DIR}/etc/hosts" /etc/hosts

# Timezone
if [ -f "${PRESEED_DIR}/etc/timezone" ]; then
    cp "${PRESEED_DIR}/etc/timezone" /etc/timezone
    ln -sf "/usr/share/zoneinfo/$(cat /etc/timezone)" /etc/localtime
    log "  - Timezone set to: $(cat /etc/timezone)"
fi

# ============================================
# 2. Apply Network Configuration
# ============================================
log "[2/7] Applying network configuration..."

# Netplan
if [ -d "${PRESEED_DIR}/network/netplan" ]; then
    mkdir -p /etc/netplan
    cp -a "${PRESEED_DIR}/network/netplan/"* /etc/netplan/ 2>/dev/null || true
    log "  - Netplan configs restored"
fi

# WireGuard
if [ -d "${PRESEED_DIR}/network/wireguard" ]; then
    mkdir -p /etc/wireguard
    cp "${PRESEED_DIR}/network/wireguard/"*.conf /etc/wireguard/ 2>/dev/null || true
    chmod 600 /etc/wireguard/*.conf 2>/dev/null || true
    log "  - WireGuard configs restored"
fi

# ============================================
# 3. Apply User Accounts
# ============================================
log "[3/7] Applying user accounts..."

# Create users from preseed
if [ -f "${PRESEED_DIR}/users/passwd" ]; then
    while IFS=: read -r username _ uid gid gecos home shell; do
        if ! id "$username" &>/dev/null; then
            useradd -u "$uid" -g "$gid" -d "$home" -s "$shell" -c "$gecos" "$username" 2>/dev/null || true
            log "  - Created user: $username"
        fi
    done < "${PRESEED_DIR}/users/passwd"
fi

# Apply password hashes
if [ -f "${PRESEED_DIR}/users/shadow" ]; then
    while IFS=: read -r username hash _; do
        if [ -n "$hash" ] && [ "$hash" != "*" ] && [ "$hash" != "!" ]; then
            usermod -p "$hash" "$username" 2>/dev/null || true
        fi
    done < "${PRESEED_DIR}/users/shadow"
    log "  - User passwords restored"
fi

# Root password
if [ -f "${PRESEED_DIR}/users/root-shadow" ]; then
    hash=$(cut -d: -f2 "${PRESEED_DIR}/users/root-shadow")
    if [ -n "$hash" ] && [ "$hash" != "*" ] && [ "$hash" != "!" ]; then
        usermod -p "$hash" root 2>/dev/null || true
        log "  - Root password restored"
    fi
fi

# SSH authorized keys
if [ -d "${PRESEED_DIR}/users/ssh" ]; then
    for userdir in "${PRESEED_DIR}/users/ssh/"*; do
        [ -d "$userdir" ] || continue
        username=$(basename "$userdir")
        if [ "$username" = "root" ]; then
            home="/root"
        else
            home="/home/$username"
        fi
        mkdir -p "${home}/.ssh"
        cp "${userdir}/authorized_keys" "${home}/.ssh/" 2>/dev/null || true
        chmod 700 "${home}/.ssh"
        chmod 600 "${home}/.ssh/authorized_keys" 2>/dev/null || true
        [ "$username" != "root" ] && chown -R "${username}:${username}" "${home}/.ssh" 2>/dev/null || true
        log "  - SSH keys restored for: $username"
    done
fi

# ============================================
# 4. Apply Service Configurations
# ============================================
log "[4/7] Applying service configurations..."

# nginx sites
if [ -d "${PRESEED_DIR}/services/nginx-sites" ]; then
    mkdir -p /etc/nginx/sites-enabled
    cp -a "${PRESEED_DIR}/services/nginx-sites/"* /etc/nginx/sites-enabled/ 2>/dev/null || true
    log "  - nginx sites restored"
fi

# nginx conf.d
if [ -d "${PRESEED_DIR}/services/nginx-conf" ]; then
    mkdir -p /etc/nginx/conf.d
    cp -a "${PRESEED_DIR}/services/nginx-conf/"* /etc/nginx/conf.d/ 2>/dev/null || true
fi

# HAProxy
if [ -f "${PRESEED_DIR}/services/haproxy.cfg" ]; then
    cp "${PRESEED_DIR}/services/haproxy.cfg" /etc/haproxy/
    log "  - HAProxy config restored"
fi

# CrowdSec
if [ -d "${PRESEED_DIR}/services/crowdsec" ]; then
    mkdir -p /etc/crowdsec
    cp -a "${PRESEED_DIR}/services/crowdsec/"* /etc/crowdsec/ 2>/dev/null || true
    log "  - CrowdSec config restored"
fi

# nftables
if [ -f "${PRESEED_DIR}/services/nftables.conf" ]; then
    cp "${PRESEED_DIR}/services/nftables.conf" /etc/
    log "  - nftables rules restored"
fi

# ============================================
# 5. Apply SSL Certificates
# ============================================
log "[5/7] Applying SSL certificates..."

if [ -d "${PRESEED_DIR}/ssl/letsencrypt" ]; then
    mkdir -p /etc/letsencrypt
    cp -a "${PRESEED_DIR}/ssl/letsencrypt/"* /etc/letsencrypt/ 2>/dev/null || true
    log "  - Let's Encrypt certs restored"
fi

if [ -d "${PRESEED_DIR}/ssl/secubox" ]; then
    mkdir -p /etc/ssl/secubox
    cp -a "${PRESEED_DIR}/ssl/secubox/"* /etc/ssl/secubox/ 2>/dev/null || true
    log "  - Custom SSL certs restored"
fi

# ============================================
# 6. Install Additional Packages
# ============================================
log "[6/7] Checking additional packages..."

if [ -f "${PRESEED_DIR}/packages/secubox-packages.list" ]; then
    # Check for packages not installed
    while read -r pkg status; do
        if [ "$status" = "install" ] && ! dpkg -l "$pkg" &>/dev/null; then
            log "  - Package needed: $pkg"
            # Could auto-install: apt-get install -y "$pkg"
        fi
    done < "${PRESEED_DIR}/packages/secubox-packages.list"
fi

# ============================================
# 7. Restart Services (SKIP on live boot to prevent hang)
# ============================================
log "[7/7] Service activation..."

# On live boot, skip ALL service operations - they cause hangs
# Services will be properly started after installation
if [ -f /run/live/medium ] || [ -d /run/live ]; then
    log "  - Live boot detected, skipping service restarts"
    log "  - Services will be activated after installation"
else
    # Only on installed systems: apply network and restart services
    log "  - Installed system detected, activating services..."

    # Apply netplan (background, don't wait)
    if command -v netplan &>/dev/null; then
        netplan apply &>/dev/null &
        log "  - netplan apply triggered (background)"
    fi

    # Restart services in background to not block boot
    for svc in nginx haproxy crowdsec nftables; do
        if [ -f "/lib/systemd/system/${svc}.service" ] || [ -f "/etc/systemd/system/${svc}.service" ]; then
            systemctl restart "$svc" &>/dev/null &
            log "  - Restart triggered: $svc"
        fi
    done

    # WireGuard interfaces
    for conf in /etc/wireguard/*.conf; do
        [ -f "$conf" ] || continue
        iface=$(basename "$conf" .conf)
        systemctl enable "wg-quick@${iface}" &>/dev/null || true
        systemctl start "wg-quick@${iface}" &>/dev/null &
        log "  - WireGuard triggered: $iface"
    done

    # Brief wait for background jobs, but don't block
    sleep 2
fi

# ============================================
# Cleanup
# ============================================
rm -rf "$PRESEED_DIR"

# Mark as applied
mkdir -p /var/lib/secubox
touch "$MARKER"
echo "applied=$(date -Iseconds)" >> "$MARKER"
echo "source=${export_hostname:-unknown}" >> "$MARKER"

log "=== Preseed Apply Complete ==="
log "Configuration restored from: ${export_hostname:-preseed}"
