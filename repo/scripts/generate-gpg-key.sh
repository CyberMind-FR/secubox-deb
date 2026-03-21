#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  SecuBox APT Repo — Génération clé GPG pour signature packages
#  Usage : bash generate-gpg-key.sh
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

GPG_HOME="${GPG_HOME:-/var/lib/secubox-repo/gpg}"
KEY_EMAIL="packages@secubox.in"
KEY_NAME="SecuBox Package Signing Key"
KEY_COMMENT="apt.secubox.in"
EXPORT_DIR="${EXPORT_DIR:-./}"

RED='\033[0;31m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${CYAN}[gpg]${NC} $*"; }
ok()  { echo -e "${GREEN}[OK]${NC} $*"; }
err() { echo -e "${RED}[ERR]${NC} $*" >&2; exit 1; }

# Vérifier si la clé existe déjà
if gpg --homedir "${GPG_HOME}" --list-keys "${KEY_EMAIL}" &>/dev/null; then
  log "Clé GPG existe déjà pour ${KEY_EMAIL}"
  gpg --homedir "${GPG_HOME}" --list-keys "${KEY_EMAIL}"
  exit 0
fi

log "Création clé GPG pour ${KEY_EMAIL}..."

mkdir -p "${GPG_HOME}"
chmod 700 "${GPG_HOME}"

# Générer la clé (sans passphrase pour CI/CD)
cat > "${GPG_HOME}/gen-key-params" <<EOF
%echo Generating SecuBox package signing key
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
Name-Real: ${KEY_NAME}
Name-Comment: ${KEY_COMMENT}
Name-Email: ${KEY_EMAIL}
Expire-Date: 0
%no-protection
%commit
%echo Key generated
EOF

gpg --homedir "${GPG_HOME}" --batch --gen-key "${GPG_HOME}/gen-key-params"
rm -f "${GPG_HOME}/gen-key-params"

ok "Clé GPG créée"

# Exporter la clé publique
log "Export clé publique..."
gpg --homedir "${GPG_HOME}" --armor --export "${KEY_EMAIL}" > "${EXPORT_DIR}/secubox-keyring.gpg"
gpg --homedir "${GPG_HOME}" --export "${KEY_EMAIL}" > "${EXPORT_DIR}/secubox-keyring.gpg.bin"

ok "Clé publique exportée : ${EXPORT_DIR}/secubox-keyring.gpg"

# Afficher fingerprint
log "Fingerprint :"
gpg --homedir "${GPG_HOME}" --fingerprint "${KEY_EMAIL}"

echo ""
echo -e "${GREEN}════════════════════════════════════════════${NC}"
echo "  Clé GPG SecuBox créée avec succès"
echo ""
echo "  Email      : ${KEY_EMAIL}"
echo "  GPG Home   : ${GPG_HOME}"
echo "  Public Key : ${EXPORT_DIR}/secubox-keyring.gpg"
echo ""
echo "  Pour les utilisateurs :"
echo "    curl -fsSL https://apt.secubox.in/secubox-keyring.gpg | sudo tee /usr/share/keyrings/secubox.gpg"
echo -e "${GREEN}════════════════════════════════════════════${NC}"
