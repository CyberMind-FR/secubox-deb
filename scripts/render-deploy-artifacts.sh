#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# scripts/render-deploy-artifacts.sh
# Generate the nginx vhost, the DEPLOY.md recipe, install.sh, and license
# copies inside output/repo/. No network access.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$SCRIPT_DIR")"
OUT="${1:-$REPO/output/repo}"
mkdir -p "$OUT"

FPR="$(cat "$OUT/FINGERPRINT.txt" 2>/dev/null || echo 'UNKNOWN')"

cat > "$OUT/nginx-apt.conf" <<'NGINX'
# /etc/nginx/sites-available/apt.secubox.in
# Drop in, symlink to sites-enabled/, then run certbot --nginx -d apt.secubox.in.

server {
    listen 80;
    listen [::]:80;
    server_name apt.secubox.in;

    root /var/www/apt.secubox.in;

    # Let certbot serve its challenge before TLS is in place.
    location /.well-known/acme-challenge/ {
        root /var/www/apt.secubox.in;
    }

    # MIME types for apt clients.
    types {
        application/vnd.debian.binary-package  deb;
        application/pgp-keys                   gpg;
        text/plain                             txt md sha256;
    }

    # Allow directory listing under /dists and /pool only.
    location /dists/ { autoindex on; }
    location /pool/  { autoindex on; }

    # Everything else is served as static.
    location / {
        try_files $uri $uri/ =404;
    }

    access_log /var/log/nginx/apt.secubox.in.access.log;
    error_log  /var/log/nginx/apt.secubox.in.error.log;
}
NGINX

cat > "$OUT/DEPLOY.md" <<EOF
# Deploying \`apt.secubox.in\`

Generated $(date -u +%Y-%m-%dT%H:%M:%SZ). Stage was built locally; this is the
out-of-band push recipe.

## 1. rsync the tree

\`\`\`bash
rsync -avz --delete \\
  --exclude='db/' --exclude='gpg/' --exclude='conf/' \\
  $OUT/  deploy@apt.secubox.in:/var/www/apt.secubox.in/
\`\`\`

The \`db/\` and \`conf/\` directories are reprepro state and must NEVER leave
the staging host. The public keyring (\`secubox-keyring.gpg\`), the dists
tree, and the pool tree are all that need to ship.

## 2. Install the nginx vhost

\`\`\`bash
scp $OUT/nginx-apt.conf apt.secubox.in:/tmp/
ssh apt.secubox.in sudo install -m 0644 /tmp/nginx-apt.conf \\
  /etc/nginx/sites-available/apt.secubox.in
ssh apt.secubox.in sudo ln -sf \\
  /etc/nginx/sites-available/apt.secubox.in \\
  /etc/nginx/sites-enabled/apt.secubox.in
ssh apt.secubox.in sudo nginx -t
ssh apt.secubox.in sudo systemctl reload nginx
\`\`\`

## 3. Issue the TLS certificate

\`\`\`bash
ssh apt.secubox.in sudo certbot --nginx \\
  -d apt.secubox.in \\
  --non-interactive --agree-tos \\
  -m packages@secubox.in
\`\`\`

## 4. Verify

\`\`\`bash
# Cert SAN must include apt.secubox.in (root cause of the previous failure)
openssl s_client -servername apt.secubox.in -connect apt.secubox.in:443 \\
  </dev/null 2>/dev/null \\
  | openssl x509 -noout -ext subjectAltName

# Repo install on a clean client
curl -fsSL https://apt.secubox.in/install.sh | sudo bash
sudo apt-get update
\`\`\`

## Fingerprint

GPG fingerprint of the publishing key: \`$FPR\`

The public key is served at:

    https://apt.secubox.in/secubox-keyring.gpg

License (CMSD-1.0, French authoritative):

    https://apt.secubox.in/LICENCE-CMSD-1.0.md

EOF

# Copy install.sh and licenses into the tree
install -m 0644 "$REPO/repo/install.sh" "$OUT/install.sh"
install -m 0644 "$REPO/LICENCE-CMSD-1.0.md"     "$OUT/" 2>/dev/null || \
  echo "WARN: $REPO/LICENCE-CMSD-1.0.md not found — French license missing" >&2
install -m 0644 "$REPO/LICENSE-CMSD-1.0.en.md"  "$OUT/" 2>/dev/null || \
  echo "WARN: $REPO/LICENSE-CMSD-1.0.en.md not found — English license missing" >&2

echo "Deploy artifacts written under $OUT:"
echo "  - nginx-apt.conf"
echo "  - DEPLOY.md"
echo "  - install.sh"
echo "  - LICENCE-CMSD-1.0.md (French, authoritative)"
echo "  - LICENSE-CMSD-1.0.en.md (English, informative)"
