#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: remote-ui/square — deploy.sh (SSH hot-update)
set -euo pipefail
readonly MODULE="square-deploy"

HOST=""
USER="secubox"
PORT=22
API_URL=""
API_PASS=""
SIMULATE=""

usage() {
    cat <<EOF
Usage: $0 -h HOST [options]
  -h HOST         Pi 4B IP or hostname
  -u USER         SSH user (default: secubox)
  -p PORT         SSH port (default: 22)
  --api-url URL   Override transport.api_otg_base in eye-square.toml
  --api-pass PASS Override transport.login_pass
  --sim           transport.simulate = true
  --no-sim        transport.simulate = false
EOF
    exit 1
}

while [ $# -gt 0 ]; do
    case $1 in
        -h) HOST="$2"; shift 2 ;;
        -u) USER="$2"; shift 2 ;;
        -p) PORT="$2"; shift 2 ;;
        --api-url) API_URL="$2"; shift 2 ;;
        --api-pass) API_PASS="$2"; shift 2 ;;
        --sim) SIMULATE="true"; shift ;;
        --no-sim) SIMULATE="false"; shift ;;
        *) usage ;;
    esac
done

[ -z "$HOST" ] && usage

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$(dirname "$SCRIPT_DIR")/.." && pwd)"
COMMON_SRC="$(dirname "$SCRIPT_DIR")/common"
ROUND_SRC="$(dirname "$SCRIPT_DIR")/round"

echo "[$MODULE] Rsync remote-ui/common/ → ${USER}@${HOST}:/var/www/common/"
rsync -avz --delete -e "ssh -p $PORT" "$COMMON_SRC/" "${USER}@${HOST}:/tmp/secubox-common/"

echo "[$MODULE] Rsync remote-ui/round/index.html → ${USER}@${HOST}:/var/www/secubox-round/"
scp -P "$PORT" "$ROUND_SRC/index.html" "${USER}@${HOST}:/tmp/index.html"

echo "[$MODULE] Rsync remote-ui/square/square-bridge.js"
scp -P "$PORT" "$SCRIPT_DIR/square-bridge.js" "${USER}@${HOST}:/tmp/square-bridge.js"

echo "[$MODULE] Rsync helper + right_panel Python packages..."
rsync -avz --delete -e "ssh -p $PORT" \
    "$REPO_ROOT/packages/secubox-eye-square/helper/eye_square_helper/" \
    "${USER}@${HOST}:/tmp/eye_square_helper/"
rsync -avz --delete -e "ssh -p $PORT" \
    "$REPO_ROOT/packages/secubox-eye-square/right_panel/secubox_eye_square_right_panel/" \
    "${USER}@${HOST}:/tmp/secubox_eye_square_right_panel/"

ssh -p "$PORT" "${USER}@${HOST}" "bash -s" <<REMOTE_SCRIPT
set -e

sudo rm -rf /var/www/common
sudo mv /tmp/secubox-common /var/www/common
sudo chown -R www-data:www-data /var/www/common

sudo cp /tmp/index.html /var/www/secubox-round/index.html
sudo sed -i 's|</body>|<script src="/local/square-bridge.js"></script></body>|' /var/www/secubox-round/index.html
sudo chown www-data:www-data /var/www/secubox-round/index.html

sudo mkdir -p /var/www/secubox-square
sudo mv /tmp/square-bridge.js /var/www/secubox-square/
sudo chown www-data:www-data /var/www/secubox-square/square-bridge.js

sudo rm -rf /usr/lib/python3/dist-packages/eye_square_helper
sudo mv /tmp/eye_square_helper /usr/lib/python3/dist-packages/
sudo rm -rf /usr/lib/python3/dist-packages/secubox_eye_square_right_panel
sudo mv /tmp/secubox_eye_square_right_panel /usr/lib/python3/dist-packages/

TOML=/etc/secubox/eye-square.toml
[ -f "\$TOML" ] || { echo "ERROR: \$TOML missing"; exit 1; }
${API_URL:+sudo sed -i "s|^api_otg_base.*|api_otg_base = \\\"$API_URL\\\"|" \$TOML}
${API_PASS:+sudo sed -i "s|^login_pass.*|login_pass = \\\"$API_PASS\\\"|" \$TOML}
${SIMULATE:+sudo sed -i "s|^simulate.*|simulate = $SIMULATE|" \$TOML}

sudo systemctl reload nginx
sudo systemctl restart secubox-eye-square-helper.service
sudo systemctl restart secubox-square-chromium.service
sudo systemctl restart secubox-square-right-panel.service

curl -fsS http://localhost/ | head -1
echo "[remote] deploy complete"
REMOTE_SCRIPT

echo "[$MODULE] Done."
