#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Idempotent standalone install for Debian bookworm (arm64/x86_64).
# For SecuBox, prefer the .deb (debian/). This script does the same by hand.
set -euo pipefail

PREFIX=/usr/lib/secubox/billets
DATA=/var/lib/secubox/billets
SECRETS=/etc/secubox/secrets
SRC="$(cd "$(dirname "$0")/.." && pwd)"

id -u secubox >/dev/null 2>&1 || \
  adduser --system --group --no-create-home --home /var/lib/secubox \
    --shell /usr/sbin/nologin secubox

install -d -o secubox -g secubox -m 0755 "$DATA" "$DATA/revisions"
install -d -o secubox -g secubox -m 0700 "$SECRETS"
install -d -o root -g root -m 1777 /run/secubox

# Signing secret (once; 0600 secubox).
if [ ! -s "$SECRETS/billets" ]; then
  umask 077
  head -c 48 /dev/urandom | base64 | tr -d '\n' > "$SECRETS/billets"
  chown secubox:secubox "$SECRETS/billets"; chmod 0600 "$SECRETS/billets"
fi

# Code + venv.
install -d "$PREFIX"
cp -r "$SRC/api" "$PREFIX/"
install -m 0644 "$SRC/requirements.txt" "$PREFIX/requirements.txt"
python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install --upgrade pip >/dev/null
"$PREFIX/venv/bin/pip" install -r "$PREFIX/requirements.txt"
chown -R secubox:secubox "$PREFIX"

# systemd + nginx.
install -m 0644 "$SRC/deploy/billets.service" /etc/systemd/system/secubox-billets.service
install -d /etc/nginx/sites-available
install -m 0644 "$SRC/deploy/nginx.conf" /etc/nginx/sites-available/billets.conf
getent group secubox >/dev/null && adduser www-data secubox >/dev/null 2>&1 || true

systemctl daemon-reload
systemctl enable --now secubox-billets.service
nginx -t && systemctl reload nginx || true

echo "billets installed. Create the author:"
echo "  sudo -u secubox $PREFIX/venv/bin/python -m api.manage create-author admin"
echo "(run from $PREFIX). Then browse the vhost and /admin."
