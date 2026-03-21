#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  SecuBox APT Repo — Setup du serveur apt.secubox.in
#  Usage : sudo bash setup-repo-server.sh
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

DOMAIN="apt.secubox.in"
REPO_DIR="/var/www/${DOMAIN}"
REPO_BASE="/var/lib/secubox-repo"
DEPLOY_USER="deploy"

RED='\033[0;31m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${CYAN}[setup]${NC} $*"; }
ok()  { echo -e "${GREEN}[OK]${NC} $*"; }
err() { echo -e "${RED}[ERR]${NC} $*" >&2; exit 1; }

[[ $EUID -ne 0 ]] && err "Ce script doit être exécuté en root"

log "=== Setup apt.secubox.in ==="

# 1. Installer les dépendances
log "Installation des dépendances..."
apt-get update
apt-get install -y nginx certbot python3-certbot-nginx reprepro gnupg rsync

# 2. Créer l'utilisateur deploy
if ! id -u "${DEPLOY_USER}" &>/dev/null; then
  log "Création utilisateur ${DEPLOY_USER}..."
  adduser --system --group --home /home/${DEPLOY_USER} --shell /bin/bash ${DEPLOY_USER}
  mkdir -p /home/${DEPLOY_USER}/.ssh
  chmod 700 /home/${DEPLOY_USER}/.ssh
  chown -R ${DEPLOY_USER}:${DEPLOY_USER} /home/${DEPLOY_USER}
  ok "Utilisateur ${DEPLOY_USER} créé"
fi

# 3. Créer les répertoires
log "Création des répertoires..."
mkdir -p "${REPO_DIR}"/{dists,pool}
mkdir -p "${REPO_BASE}"/{conf,gpg}
chmod 700 "${REPO_BASE}/gpg"

chown -R ${DEPLOY_USER}:${DEPLOY_USER} "${REPO_DIR}"
chown -R ${DEPLOY_USER}:${DEPLOY_USER} "${REPO_BASE}"

# 4. Copier la configuration reprepro
log "Configuration reprepro..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

cat > "${REPO_BASE}/conf/distributions" <<'EOF'
Origin: SecuBox
Label: SecuBox
Suite: bookworm
Codename: bookworm
Version: 12.0
Architectures: arm64 amd64 source
Components: main
Description: SecuBox Debian packages for Armada/x86_64
SignWith: packages@secubox.in
Contents: percomponent nocompatsymlink

Origin: SecuBox
Label: SecuBox
Suite: trixie
Codename: trixie
Version: 13.0
Architectures: arm64 amd64 source
Components: main
Description: SecuBox Debian packages (testing)
SignWith: packages@secubox.in
Contents: percomponent nocompatsymlink
EOF

cat > "${REPO_BASE}/conf/options" <<EOF
verbose
basedir ${REPO_BASE}
outdir ${REPO_DIR}
gnupghome ${REPO_BASE}/gpg
EOF

# 5. Générer la clé GPG
if ! sudo -u ${DEPLOY_USER} gpg --homedir "${REPO_BASE}/gpg" --list-keys "packages@secubox.in" &>/dev/null; then
  log "Génération clé GPG..."

  cat > "${REPO_BASE}/gpg/gen-key-params" <<EOF
%echo Generating SecuBox package signing key
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
Name-Real: SecuBox Package Signing Key
Name-Comment: apt.secubox.in
Name-Email: packages@secubox.in
Expire-Date: 0
%no-protection
%commit
%echo Key generated
EOF

  sudo -u ${DEPLOY_USER} gpg --homedir "${REPO_BASE}/gpg" --batch --gen-key "${REPO_BASE}/gpg/gen-key-params"
  rm -f "${REPO_BASE}/gpg/gen-key-params"

  # Exporter la clé publique
  sudo -u ${DEPLOY_USER} gpg --homedir "${REPO_BASE}/gpg" --armor --export "packages@secubox.in" > "${REPO_DIR}/secubox-keyring.gpg"
  sudo -u ${DEPLOY_USER} gpg --homedir "${REPO_BASE}/gpg" --export "packages@secubox.in" > "${REPO_DIR}/secubox-keyring.gpg.bin"

  ok "Clé GPG générée et exportée"
fi

# 6. Configurer nginx
log "Configuration nginx..."
cat > /etc/nginx/sites-available/${DOMAIN} <<'NGINX_CONF'
server {
    listen 80;
    listen [::]:80;
    server_name apt.secubox.in;

    root /var/www/apt.secubox.in;
    autoindex on;

    access_log /var/log/nginx/apt.secubox.in.access.log;
    error_log /var/log/nginx/apt.secubox.in.error.log;

    location = /secubox-keyring.gpg {
        add_header Content-Type application/pgp-keys;
    }

    location /dists/ {
        autoindex on;
    }

    location /pool/ {
        autoindex on;
    }

    location ~ /\. {
        deny all;
    }
}
NGINX_CONF

ln -sf /etc/nginx/sites-available/${DOMAIN} /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
ok "nginx configuré"

# 7. Certificat Let's Encrypt
log "Obtention certificat SSL..."
certbot --nginx -d ${DOMAIN} --non-interactive --agree-tos -m admin@secubox.in || \
  log "Certbot a échoué — configurer manuellement avec: certbot --nginx -d ${DOMAIN}"

# 8. Créer un fichier index.html
cat > "${REPO_DIR}/index.html" <<'HTML'
<!DOCTYPE html>
<html>
<head>
  <title>SecuBox APT Repository</title>
  <style>
    body { font-family: sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
    code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }
    pre { background: #1e1e2e; color: #cdd6f4; padding: 15px; border-radius: 5px; overflow-x: auto; }
    h1 { color: #89b4fa; }
    a { color: #89b4fa; }
  </style>
</head>
<body>
  <h1>🔐 SecuBox APT Repository</h1>
  <p>Debian packages pour SecuBox (arm64, amd64)</p>

  <h2>Installation</h2>
  <pre>
# Ajouter la clé GPG
curl -fsSL https://apt.secubox.in/secubox-keyring.gpg | sudo tee /usr/share/keyrings/secubox.gpg > /dev/null

# Ajouter le repository
echo "deb [signed-by=/usr/share/keyrings/secubox.gpg] https://apt.secubox.in bookworm main" | \
  sudo tee /etc/apt/sources.list.d/secubox.list

# Installer SecuBox
sudo apt update
sudo apt install secubox-full
  </pre>

  <h2>Packages disponibles</h2>
  <ul>
    <li><code>secubox-full</code> — Installation complète (tous les modules)</li>
    <li><code>secubox-lite</code> — Installation minimale (ESPRESSObin)</li>
    <li><code>secubox-core</code> — Bibliothèque commune</li>
  </ul>

  <h2>Liens</h2>
  <ul>
    <li><a href="/dists/">Distributions</a></li>
    <li><a href="/pool/">Pool de packages</a></li>
    <li><a href="/secubox-keyring.gpg">Clé GPG (ASCII)</a></li>
  </ul>

  <p><a href="https://github.com/CyberMind/secubox-deb">GitHub</a> | <a href="https://secubox.gondwana.systems">Documentation</a></p>
</body>
</html>
HTML

chown ${DEPLOY_USER}:${DEPLOY_USER} "${REPO_DIR}/index.html"

ok "Setup terminé !"
echo ""
echo -e "${GREEN}════════════════════════════════════════════${NC}"
echo "  apt.secubox.in configuré"
echo ""
echo "  Repository : ${REPO_DIR}"
echo "  reprepro   : ${REPO_BASE}"
echo "  GPG Key    : ${REPO_DIR}/secubox-keyring.gpg"
echo ""
echo "  Ajouter des packages :"
echo "    sudo -u ${DEPLOY_USER} reprepro -b ${REPO_BASE} includedeb bookworm *.deb"
echo ""
echo "  Clé SSH deploy à ajouter dans /home/${DEPLOY_USER}/.ssh/authorized_keys"
echo -e "${GREEN}════════════════════════════════════════════${NC}"
