#!/usr/bin/env bash
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
# Lire depuis /boot/admin_password si présent, sinon générer un aléatoire
if [[ -f "${BOOT_DIR}/admin_password" ]]; then
  ADMIN_PASS=$(cat "${BOOT_DIR}/admin_password" | tr -d '\n')
else
  ADMIN_PASS=$(openssl rand -base64 12)
  echo "ADMIN PASSWORD: ${ADMIN_PASS}" > "${BOOT_DIR}/admin_password_generated.txt"
  log "Mot de passe admin généré — voir ${BOOT_DIR}/admin_password_generated.txt"
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

# ── 8. Certificat TLS autosigné ──────────────────────────────────
if [[ ! -f "${TLS_DIR}/cert.pem" ]]; then
  openssl req -x509 -newkey rsa:4096 -days 3650 \
    -keyout "${TLS_DIR}/key.pem" \
    -out    "${TLS_DIR}/cert.pem" \
    -nodes -subj "/CN=${HOSTNAME}/O=CyberMind SecuBox/C=FR" \
    -addext "subjectAltName=DNS:${HOSTNAME},DNS:secubox.local,IP:192.168.1.1" \
    2>/dev/null
  chown -R secubox:secubox "${TLS_DIR}"
  chmod 640 "${TLS_DIR}/key.pem"
  ok "Certificat TLS autosigné généré"
fi

# ── 9. Activer nginx ──────────────────────────────────────────────
if [[ -f /etc/nginx/sites-available/secubox ]]; then
  ln -sf /etc/nginx/sites-available/secubox /etc/nginx/sites-enabled/secubox 2>/dev/null || true
  rm -f /etc/nginx/sites-enabled/default
  nginx -t && systemctl reload nginx 2>/dev/null || true
fi

# ── 10. nftables — règles de base ────────────────────────────────
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

log "=== First boot terminé ==="
log "Interface : https://${HOSTNAME}/ ou https://$(hostname -I | awk '{print $1}')/"
log "Login     : admin / ${ADMIN_PASS}"
