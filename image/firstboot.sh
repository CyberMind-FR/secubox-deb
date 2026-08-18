#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# ══════════════════════════════════════════════════════════════════
#  SecuBox-DEB — firstboot.sh
#  Exécuté une seule fois au premier démarrage (systemd one-shot)
#  - Génère le JWT secret
#  - Configure SSH (clé depuis /boot/authorized_keys)
#  - Crée /etc/secubox/secubox.conf
#  - Génère certificat TLS autosigné
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

SECUBOX_DIR="/etc/secubox"
SECUBOX_RUN="/run/secubox"
SECUBOX_DATA="/var/lib/secubox"
TLS_DIR="${SECUBOX_DIR}/tls"
BOOT_DIR="/boot"

log() { echo "[firstboot] $*" | systemd-cat -t secubox-firstboot -p info 2>/dev/null || echo "[firstboot] $*"; }
ok()  { echo "[firstboot] OK: $*" | systemd-cat -t secubox-firstboot -p info 2>/dev/null || echo "[firstboot] OK: $*"; }

log "=== SecuBox First Boot ==="

# ── 0. Expand filesystem to use all available space ─────────────────
expand_filesystem() {
    log "Checking for filesystem expansion..."

    # Find the root device
    local root_dev root_part root_disk part_num
    root_dev=$(findmnt -n -o SOURCE / 2>/dev/null | head -1)

    # Handle overlay filesystems (get the underlying device)
    if [[ "$root_dev" == "overlay" ]] || [[ "$root_dev" == "overlayfs" ]]; then
        # Try to find the actual root from /proc/cmdline
        root_dev=$(grep -oP 'root=\K[^ ]+' /proc/cmdline 2>/dev/null || echo "")
        if [[ "$root_dev" == "LABEL="* ]]; then
            local label="${root_dev#LABEL=}"
            root_dev=$(blkid -L "$label" 2>/dev/null || echo "")
        elif [[ "$root_dev" == "UUID="* ]]; then
            local uuid="${root_dev#UUID=}"
            root_dev=$(blkid -U "$uuid" 2>/dev/null || echo "")
        fi
    fi

    if [[ -z "$root_dev" ]] || [[ ! -b "$root_dev" ]]; then
        log "Could not determine root device - skipping expansion"
        return 0
    fi

    log "Root device: $root_dev"

    # Parse device and partition number
    # Handle both /dev/mmcblk0p2 and /dev/sda2 styles
    if [[ "$root_dev" =~ ^(/dev/[a-z]+)([0-9]+)$ ]]; then
        root_disk="${BASH_REMATCH[1]}"
        part_num="${BASH_REMATCH[2]}"
    elif [[ "$root_dev" =~ ^(/dev/[a-z]+[0-9]+)p([0-9]+)$ ]]; then
        root_disk="${BASH_REMATCH[1]}"
        part_num="${BASH_REMATCH[2]}"
    elif [[ "$root_dev" =~ ^(/dev/nvme[0-9]+n[0-9]+)p([0-9]+)$ ]]; then
        root_disk="${BASH_REMATCH[1]}"
        part_num="${BASH_REMATCH[2]}"
    else
        log "Could not parse device name: $root_dev"
        return 0
    fi

    log "Disk: $root_disk, Partition: $part_num"

    # Check if this is the last partition (the one we should expand)
    # For our layout: p1=boot/ESP, p2=rootfs, p3=data
    # We want to expand p3 (data) or p2 if no p3 exists

    # Count partitions
    local part_count
    if [[ "$root_disk" == /dev/mmcblk* ]] || [[ "$root_disk" == /dev/nvme* ]]; then
        part_count=$(ls -1 "${root_disk}p"* 2>/dev/null | wc -l)
    else
        part_count=$(ls -1 "${root_disk}"[0-9]* 2>/dev/null | wc -l)
    fi

    # Find the last partition
    local last_part_num=$part_count
    local last_part
    if [[ "$root_disk" == /dev/mmcblk* ]] || [[ "$root_disk" == /dev/nvme* ]]; then
        last_part="${root_disk}p${last_part_num}"
    else
        last_part="${root_disk}${last_part_num}"
    fi

    log "Last partition: $last_part (total: $part_count partitions)"

    # Check if there's unused space after last partition
    local disk_size_sectors part_end_sectors
    disk_size_sectors=$(blockdev --getsz "$root_disk" 2>/dev/null || echo 0)

    if [[ $disk_size_sectors -eq 0 ]]; then
        log "Could not determine disk size"
        return 0
    fi

    # Get end of last partition using parted
    part_end_sectors=$(parted -s "$root_disk" unit s print 2>/dev/null | \
        awk -v pnum="$last_part_num" '$1 == pnum { gsub("s","",$3); print $3 }')

    if [[ -z "$part_end_sectors" ]]; then
        log "Could not determine partition end"
        return 0
    fi

    # Calculate free space (subtract 2048 sectors for safety margin)
    local free_sectors=$((disk_size_sectors - part_end_sectors - 2048))
    local free_mb=$((free_sectors * 512 / 1024 / 1024))

    log "Disk size: $((disk_size_sectors * 512 / 1024 / 1024)) MB"
    log "Partition end: $((part_end_sectors * 512 / 1024 / 1024)) MB"
    log "Free space: ${free_mb} MB"

    # Only expand if there's significant free space (> 100MB)
    if [[ $free_mb -lt 100 ]]; then
        log "Not enough free space to expand (${free_mb}MB < 100MB)"
        return 0
    fi

    log "=== Expanding partition $last_part_num to use ${free_mb}MB of free space ==="

    # Use growpart if available (cleaner), otherwise use parted
    if command -v growpart &>/dev/null; then
        log "Using growpart to expand partition..."
        if growpart "$root_disk" "$last_part_num" 2>&1; then
            ok "Partition expanded with growpart"
        else
            warn "growpart failed, trying parted..."
            # Fallback to parted
            parted -s "$root_disk" resizepart "$last_part_num" 100% 2>&1 || \
                warn "Partition expansion failed"
        fi
    else
        log "Using parted to expand partition..."
        if parted -s "$root_disk" resizepart "$last_part_num" 100% 2>&1; then
            ok "Partition expanded with parted"
        else
            warn "Partition expansion failed"
            return 0
        fi
    fi

    # Re-read partition table
    partprobe "$root_disk" 2>/dev/null || true
    sleep 2

    # Now resize the filesystem
    local fs_type
    fs_type=$(blkid -s TYPE -o value "$last_part" 2>/dev/null || echo "")

    log "Filesystem type on $last_part: $fs_type"

    case "$fs_type" in
        ext4|ext3|ext2)
            log "Resizing ext4 filesystem..."
            # resize2fs works on mounted filesystems
            if resize2fs "$last_part" 2>&1; then
                ok "ext4 filesystem expanded"
            else
                warn "resize2fs failed - may need reboot"
            fi
            ;;
        xfs)
            log "Resizing XFS filesystem..."
            # xfs_growfs needs mount point
            local mount_point
            mount_point=$(findmnt -n -o TARGET "$last_part" 2>/dev/null || echo "")
            if [[ -n "$mount_point" ]]; then
                xfs_growfs "$mount_point" 2>&1 || warn "xfs_growfs failed"
            else
                warn "XFS partition not mounted - cannot resize"
            fi
            ;;
        btrfs)
            log "Resizing Btrfs filesystem..."
            local mount_point
            mount_point=$(findmnt -n -o TARGET "$last_part" 2>/dev/null || echo "")
            if [[ -n "$mount_point" ]]; then
                btrfs filesystem resize max "$mount_point" 2>&1 || warn "btrfs resize failed"
            fi
            ;;
        *)
            log "Unknown filesystem type: $fs_type - skipping resize"
            ;;
    esac

    # Show new sizes
    log "New partition layout:"
    lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINT "$root_disk" 2>/dev/null || true

    ok "Filesystem expansion complete"
}

# Run expansion
expand_filesystem

# ── 1. Créer l'utilisateur système secubox ────────────────────────
if ! id -u secubox >/dev/null 2>&1; then
  adduser --system --group --no-create-home \
    --home "${SECUBOX_DATA}" --shell /usr/sbin/nologin secubox
  ok "Utilisateur secubox créé"
fi

# ── 2. Répertoires ────────────────────────────────────────────────
install -d -o secubox -g secubox -m 750 "${SECUBOX_DIR}"
install -d -o secubox -g secubox -m 750 "${SECUBOX_RUN}"
install -d -o secubox -g secubox -m 750 "${SECUBOX_DATA}"
install -d -o secubox -g secubox -m 750 "${TLS_DIR}"
install -d -o root    -g secubox -m 750 "${SECUBOX_DIR}/netmodes"
ok "Répertoires créés"

# ── 3. Hostname depuis /boot/hostname ─────────────────────────────
if [[ -f "${BOOT_DIR}/hostname" ]]; then
  NEW_HOSTNAME=$(cat "${BOOT_DIR}/hostname" | tr -cd 'a-zA-Z0-9-' | head -c 32)
  if [[ -n "${NEW_HOSTNAME}" ]]; then
    hostnamectl set-hostname "${NEW_HOSTNAME}"
    log "Hostname configuré: ${NEW_HOSTNAME}"
  fi
fi

# ── 4. SSH — injection clé publique ──────────────────────────────
install -d -o root -g root -m 700 /root/.ssh
if [[ -f "${BOOT_DIR}/authorized_keys" ]]; then
  cat "${BOOT_DIR}/authorized_keys" > /root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys
  ok "Clés SSH injectées depuis ${BOOT_DIR}/authorized_keys"
else
  log "Pas de ${BOOT_DIR}/authorized_keys — SSH password auth activé provisoirement"
  sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
  systemctl reload ssh 2>/dev/null || true
fi

# Désactiver SSH root password en prod si clé présente
if [[ -s /root/.ssh/authorized_keys ]]; then
  sed -i 's/^#PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
  sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/'  /etc/ssh/sshd_config
  systemctl reload ssh 2>/dev/null || true
fi

# ── 5. JWT Secret ─────────────────────────────────────────────────
JWT_SECRET=$(openssl rand -hex 32)
ok "JWT secret généré"

# ── 6. Mot de passe admin par défaut ──────────────────────────────
# Lire depuis /boot/admin_password si présent, sinon utiliser "secubox"
if [[ -f "${BOOT_DIR}/admin_password" ]]; then
  ADMIN_PASS=$(cat "${BOOT_DIR}/admin_password" | tr -d '\n')
  log "Mot de passe admin lu depuis ${BOOT_DIR}/admin_password"
else
  ADMIN_PASS="secubox"
  log "Mot de passe admin par défaut: secubox"
fi

# ── 7. Écrire /etc/secubox/secubox.conf ──────────────────────────
HOSTNAME=$(hostname)
# Détecter board : ARM via device-tree, x64 via hostname ou DMI
if [[ -f /proc/device-tree/model ]]; then
  BOARD=$(cat /proc/device-tree/model 2>/dev/null | tr -d '\0')
elif [[ "${HOSTNAME}" == *"vm-x64"* ]]; then
  BOARD="vm-x64"
elif [[ -f /sys/class/dmi/id/product_name ]]; then
  BOARD=$(cat /sys/class/dmi/id/product_name 2>/dev/null | head -1)
else
  BOARD="unknown"
fi

cat > "${SECUBOX_DIR}/secubox.conf" <<EOF
# /etc/secubox/secubox.conf — généré par firstboot
# NE PAS modifier jwt_secret manuellement

[global]
hostname  = "${HOSTNAME}"
timezone  = "Europe/Paris"
board     = "${BOARD}"
debug     = false

[api]
socket_dir  = "/run/secubox"
jwt_secret  = "${JWT_SECRET}"

[auth]
[auth.users.admin]
password = "${ADMIN_PASS}"

[crowdsec]
lapi_url = "http://127.0.0.1:8080"
lapi_key = ""

[dpi]
mode      = "inline"
engine    = "netifyd"
interface = "eth0"
mirror_if = "ifb0"

[wireguard]
interface    = "wg0"
listen_port  = 51820

[netmodes]
current_mode = "router"
backup_dir   = "/var/lib/secubox/netmodes-backup"
EOF

chown secubox:secubox "${SECUBOX_DIR}/secubox.conf"
chmod 640 "${SECUBOX_DIR}/secubox.conf"
ok "/etc/secubox/secubox.conf créé"

# ── 8. Portal users.json avec admin par défaut ───────────────────
# Schema v2 + argon2 hash (issue #210 — old SHA256 + flat schema made
# `admin` / `secubox` login fail on every fresh image).
#
# We bypass the engine.set_password path because password_policy would
# reject "secubox" as too weak — that's correct for normal use but wrong
# for a seed. Instead we write the v2 doc directly with
# `must_change_password: true` so the very next login is gated on a
# proper password change.
USERS_JSON="${SECUBOX_DIR}/users.json"
python3 - "$ADMIN_PASS" "$USERS_JSON" <<'PYEOF'
import json, sys
from datetime import datetime, timezone

try:
    from argon2 import PasswordHasher
except ImportError:
    sys.exit("firstboot: argon2 missing — install python3-argon2 (already a secubox-core dep)")

pw, path = sys.argv[1], sys.argv[2]
doc = {
    "users": [
        {
            "username": "admin",
            "email": "admin@secubox.local",
            "role": "admin",
            "enabled": True,
            "password_hash": PasswordHasher().hash(pw),
            "must_change_password": True,
            "totp": None,
            "google": None,
            "services": [],
            "created": datetime.now(timezone.utc).isoformat(),
            "last_login": None,
        }
    ]
}
with open(path, "w") as f:
    json.dump(doc, f, indent=2)
PYEOF
chown secubox:secubox "${USERS_JSON}"
chmod 640 "${USERS_JSON}"
ok "Portal users.json créé (admin / ${ADMIN_PASS}, doit changer au premier login)"

# ── 9. Certificat TLS autosigné ───────────────────────────────────
if [[ ! -f "${TLS_DIR}/cert.pem" ]]; then
  openssl req -x509 -newkey rsa:4096 -days 3650 \
    -keyout "${TLS_DIR}/key.pem" \
    -out    "${TLS_DIR}/cert.pem" \
    -nodes -subj "/CN=${HOSTNAME}/O=CyberMind SecuBox/C=FR" \
    -addext "subjectAltName=DNS:${HOSTNAME},DNS:secubox.local,IP:192.168.10.1" \
    2>/dev/null
  chown -R secubox:secubox "${TLS_DIR}"
  chmod 640 "${TLS_DIR}/key.pem"
  ok "Certificat TLS autosigné généré"
fi

# ── 10. Activer nginx ─────────────────────────────────────────────
if [[ -f /etc/nginx/sites-available/secubox ]]; then
  ln -sf /etc/nginx/sites-available/secubox /etc/nginx/sites-enabled/secubox 2>/dev/null || true
  rm -f /etc/nginx/sites-enabled/default
  nginx -t && systemctl reload nginx 2>/dev/null || true
fi

# ── 11. Network Auto-Detection ──────────────────────────────────
log "=== Network Detection ==="
# Short-circuit when the image was built with --static-ip: build-live-usb.sh
# wrote a fixed netplan AND pre-touched /var/lib/secubox/.net-configured.
# Running net-detect here would clobber the static config with router-mode
# defaults (WAN + br-lan 192.168.10.1/24), the exact regression in #128.
if [[ -f /var/lib/secubox/.net-configured ]]; then
  log "Static netplan in effect (.net-configured present) — skipping net-detect"
elif [[ -x /usr/sbin/secubox-net-detect ]]; then
  # Run detection
  /usr/sbin/secubox-net-detect detect /run/secubox/net-detect.json

  # Parse detection result
  if [[ -f /run/secubox/net-detect.json ]]; then
    DETECTED_BOARD=$(grep -o '"board": "[^"]*"' /run/secubox/net-detect.json | cut -d'"' -f4)
    DETECTED_WAN=$(grep -o '"wan": "[^"]*"' /run/secubox/net-detect.json | cut -d'"' -f4)
    DETECTED_LAN=$(grep -o '"lan": "[^"]*"' /run/secubox/net-detect.json | cut -d'"' -f4)

    log "Board: ${DETECTED_BOARD}"
    log "WAN: ${DETECTED_WAN}"
    log "LAN: ${DETECTED_LAN}"

    # Update secubox.conf with detected values
    sed -i "s/^board     = .*/board     = \"${DETECTED_BOARD}\"/" "${SECUBOX_DIR}/secubox.conf"

    # Update DPI interface
    if [[ -n "${DETECTED_WAN}" ]]; then
      sed -i "s/^interface = .*/interface = \"${DETECTED_WAN}\"/" "${SECUBOX_DIR}/secubox.conf"
    fi

    # Apply network configuration (router mode by default)
    /usr/sbin/secubox-net-detect apply router

    ok "Network auto-configured"
  fi
else
  log "secubox-net-detect not found, using static netplan"
fi

# Mark network as configured
touch /var/lib/secubox/.net-configured

# ── 12. nftables — règles de base ────────────────────────────────
cat > /etc/nftables.conf <<'NFTEOF'
#!/usr/sbin/nft -f
# SecuBox nftables — généré par firstboot
# DEFAULT DROP — ouvrir explicitement ce qui est nécessaire

flush ruleset

table inet secubox_filter {
    chain input {
        type filter hook input priority 0; policy drop;

        # Loopback toujours accepté
        iif lo accept

        # Connexions établies
        ct state established,related accept

        # ICMP/ICMPv6
        ip  protocol icmp   accept
        ip6 nexthdr  icmpv6 accept

        # SSH (port 22)
        tcp dport 22 accept

        # HTTP/HTTPS (SecuBox UI)
        tcp dport { 80, 443 } accept

        # DHCP client — accept DHCPOFFER / DHCPACK on UDP 68. The
        # conntrack `established,related` clause above doesn't help
        # for DHCP because the request goes out from 0.0.0.0:68 and
        # the reply comes back broadcast (or unicast direct to the
        # offered IP before it's actually bound), neither of which
        # match the original 5-tuple. Without this rule networkd's
        # DHCP times out and secubox-net-fallback's ARP-probe takes
        # over — operator ends up on a random fallback subnet.
        udp dport 68 accept

        # WireGuard
        udp dport 51820 accept

        # CrowdSec LAPI (local seulement)
        ip saddr 127.0.0.1 tcp dport 8080 accept

        # Drop silencieux
        drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
        ct state established,related accept
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}
NFTEOF

systemctl enable nftables
systemctl restart nftables 2>/dev/null || true
ok "nftables configuré"

# The nftables cache timer/service that powers the SOC firewall_summary
# widget is now shipped by the secubox-hub package itself (it owns the
# consuming endpoint). See:
#   packages/secubox-hub/debian/secubox-nft-cache.service
#   packages/secubox-hub/debian/secubox-nft-cache.timer
#   packages/secubox-hub/sbin/secubox-nft-cache
# Each module that needs cached external state ships its own
# cache-populator + timer; firstboot stays platform-only.

# ── Kiosk safety net ────────────────────────────────────────────────
# build-live-usb.sh touches /var/lib/secubox/.kiosk-enabled and enables
# secubox-kiosk.service at build time, but those have been observed
# missing from the booted image on bare-metal amd64 (user report
# 2026-05-24 — operator had to run `secubox-kiosk-setup enable`
# manually to land in kiosk mode). Call the setup helper at firstboot
# if the sentinel isn't present — idempotent, leaves a working build
# alone, recovers a broken one.
if [[ -x /usr/sbin/secubox-kiosk-setup ]]; then
    if [[ ! -f /var/lib/secubox/.kiosk-enabled ]]; then
        log "Kiosk sentinel missing — running secubox-kiosk-setup enable"
        if /usr/sbin/secubox-kiosk-setup enable --x11; then
            ok "Kiosk enabled (X11)"
        else
            log "Kiosk enable failed — leaving in console mode"
        fi
    else
        log "Kiosk sentinel already present, skipping setup"
    fi
fi

log "=== First boot terminé ==="
log "Interface : https://${HOSTNAME}/ ou https://$(hostname -I | awk '{print $1}')/"
log "Login     : admin / ${ADMIN_PASS}"
