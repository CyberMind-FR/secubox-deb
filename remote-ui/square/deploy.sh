#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: remote-ui/square — deploy.sh (SSH hot-update)
# Phase 3: pushes helper + kiosk Python packages, applies optional config
# overrides, restarts secubox-eye-square-helper + secubox-square-kiosk.
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

echo "[$MODULE] Rsync helper + kiosk Python packages..."
rsync -avz --delete -e "ssh -p $PORT" \
    "$REPO_ROOT/packages/secubox-eye-square/helper/eye_square_helper/" \
    "${USER}@${HOST}:/tmp/eye_square_helper/"
rsync -avz --delete -e "ssh -p $PORT" \
    "$REPO_ROOT/packages/secubox-eye-square/kiosk/secubox_eye_square_kiosk/" \
    "${USER}@${HOST}:/tmp/secubox_eye_square_kiosk/"

ssh -p "$PORT" "${USER}@${HOST}" "bash -s" <<REMOTE_SCRIPT
set -e

sudo rm -rf /usr/lib/python3/dist-packages/eye_square_helper
sudo mv /tmp/eye_square_helper /usr/lib/python3/dist-packages/
sudo rm -rf /usr/lib/python3/dist-packages/secubox_eye_square_kiosk
sudo mv /tmp/secubox_eye_square_kiosk /usr/lib/python3/dist-packages/

TOML=/etc/secubox/eye-square.toml
[ -f "\$TOML" ] || { echo "ERROR: \$TOML missing"; exit 1; }
${API_URL:+sudo sed -i "s|^api_otg_base.*|api_otg_base = \\\"$API_URL\\\"|" \$TOML}
${API_PASS:+sudo sed -i "s|^login_pass.*|login_pass = \\\"$API_PASS\\\"|" \$TOML}
${SIMULATE:+sudo sed -i "s|^simulate.*|simulate = $SIMULATE|" \$TOML}

sudo systemctl restart secubox-eye-square-helper.service
sudo systemctl restart secubox-square-kiosk.service

systemctl is-active secubox-square-kiosk.service || true
echo "[remote] deploy complete"
REMOTE_SCRIPT

echo "[$MODULE] Done."
