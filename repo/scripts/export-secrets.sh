#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  SecuBox APT Repo — Export secrets for GitHub Actions
#  Usage : bash export-secrets.sh [--gpg-home /path]
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

GPG_HOME="${GPG_HOME:-/var/lib/secubox-repo/gpg}"
KEY_EMAIL="packages@secubox.in"
OUTPUT_DIR="${OUTPUT_DIR:-./secrets}"

RED='\033[0;31m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'; GOLD='\033[0;33m'; NC='\033[0m'
log() { echo -e "${CYAN}[export]${NC} $*"; }
ok()  { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${GOLD}[WARN]${NC} $*"; }
err() { echo -e "${RED}[ERR]${NC} $*" >&2; exit 1; }

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --gpg-home) GPG_HOME="$2"; shift 2 ;;
    --output)   OUTPUT_DIR="$2"; shift 2 ;;
    *)          err "Unknown option: $1" ;;
  esac
done

# Verify GPG key exists
if ! gpg --homedir "${GPG_HOME}" --list-keys "${KEY_EMAIL}" &>/dev/null; then
  err "GPG key not found for ${KEY_EMAIL} in ${GPG_HOME}"
fi

mkdir -p "${OUTPUT_DIR}"
chmod 700 "${OUTPUT_DIR}"

log "Exporting secrets for GitHub Actions..."

# 1. Export GPG private key
log "Exporting GPG private key..."
gpg --homedir "${GPG_HOME}" --armor --export-secret-keys "${KEY_EMAIL}" > "${OUTPUT_DIR}/GPG_PRIVATE_KEY.txt"
chmod 600 "${OUTPUT_DIR}/GPG_PRIVATE_KEY.txt"
ok "GPG_PRIVATE_KEY.txt created"

# 2. Export GPG public key
log "Exporting GPG public key..."
gpg --homedir "${GPG_HOME}" --armor --export "${KEY_EMAIL}" > "${OUTPUT_DIR}/GPG_PUBLIC_KEY.txt"
ok "GPG_PUBLIC_KEY.txt created"

# 3. Generate SSH deploy key pair
if [[ ! -f "${OUTPUT_DIR}/deploy_key" ]]; then
  log "Generating SSH deploy key pair..."
  ssh-keygen -t ed25519 -C "deploy@secubox-ci" -f "${OUTPUT_DIR}/deploy_key" -N ""
  ok "SSH deploy key generated"
else
  warn "SSH deploy key already exists, skipping"
fi

# 4. Generate known_hosts entry template
log "Creating known_hosts template..."
cat > "${OUTPUT_DIR}/KNOWN_HOSTS_TEMPLATE.txt" <<'EOF'
# Run this on the APT server to get the correct entry:
# ssh-keyscan -H apt.secubox.in

# Example format (replace with actual output from ssh-keyscan):
# |1|xxxx...|yyyy...= ssh-ed25519 AAAA...
EOF
ok "KNOWN_HOSTS_TEMPLATE.txt created"

# 5. Instructions
cat > "${OUTPUT_DIR}/GITHUB_SECRETS_INSTRUCTIONS.md" <<'EOF'
# GitHub Secrets Configuration

## Required Secrets

Add these secrets to your GitHub repository:
Settings → Secrets and variables → Actions → New repository secret

### 1. GPG_PRIVATE_KEY
Copy the entire contents of `GPG_PRIVATE_KEY.txt`:
```
-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----
```

### 2. DEPLOY_SSH_KEY
Copy the entire contents of `deploy_key` (private key):
```
-----BEGIN OPENSSH PRIVATE KEY-----
...
-----END OPENSSH PRIVATE KEY-----
```

### 3. DEPLOY_KNOWN_HOSTS
Run on the APT server and copy output:
```bash
ssh-keyscan -H apt.secubox.in
```

## APT Server Setup

1. Add the deploy public key to the server:
```bash
# On apt.secubox.in as root
cat >> /home/deploy/.ssh/authorized_keys << 'EOF'
<contents of deploy_key.pub>
EOF
chmod 600 /home/deploy/.ssh/authorized_keys
chown deploy:deploy /home/deploy/.ssh/authorized_keys
```

2. Verify connection:
```bash
# From CI runner or local machine
ssh -i deploy_key deploy@apt.secubox.in "echo OK"
```

## Verification

After setup, manually trigger the publish workflow:
1. Go to Actions → Publish Packages
2. Click "Run workflow"
3. Select branch and distribution
4. Click "Run workflow"
EOF

ok "Instructions written to GITHUB_SECRETS_INSTRUCTIONS.md"

echo ""
echo -e "${GREEN}════════════════════════════════════════════${NC}"
echo "  Secrets exported to: ${OUTPUT_DIR}"
echo ""
echo "  Files created:"
echo "    - GPG_PRIVATE_KEY.txt  → GitHub secret: GPG_PRIVATE_KEY"
echo "    - GPG_PUBLIC_KEY.txt   → For reference"
echo "    - deploy_key           → GitHub secret: DEPLOY_SSH_KEY"
echo "    - deploy_key.pub       → Add to APT server"
echo "    - GITHUB_SECRETS_INSTRUCTIONS.md"
echo ""
echo -e "  ${GOLD}IMPORTANT: Keep these files secure!${NC}"
echo "  Delete after configuring GitHub secrets."
echo -e "${GREEN}════════════════════════════════════════════${NC}"
