#!/bin/bash
# ══════════════════════════════════════════════════════════════════
# fix-namespace-errors.sh — Disable sandboxing that causes Python errors
# Run this on real hardware when services fail with:
#   "Failed to set up mount namespacing: /run/systemd/unit-root/usr/bin/python3"
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[fix]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }
err() { echo -e "${RED}[error]${NC} $*" >&2; }

if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root"
    exit 1
fi

log "Scanning for SecuBox services with sandboxing..."

# Find all secubox services with PrivateTmp or ProtectSystem
SERVICES=$(systemctl list-unit-files 'secubox-*.service' --no-legend | awk '{print $1}')

FIXED=0
for SERVICE in $SERVICES; do
    # Get the service file path
    SERVICE_FILE=$(systemctl show -p FragmentPath "$SERVICE" --value 2>/dev/null || true)
    [[ -z "$SERVICE_FILE" ]] && continue
    [[ ! -f "$SERVICE_FILE" ]] && continue

    # Check if it has sandboxing options
    if grep -qE '^(PrivateTmp|ProtectSystem)=' "$SERVICE_FILE" 2>/dev/null; then
        # Create override directory
        OVERRIDE_DIR="/etc/systemd/system/${SERVICE}.d"
        mkdir -p "$OVERRIDE_DIR"

        # Create override file
        cat > "$OVERRIDE_DIR/no-sandbox.conf" <<'EOF'
# Override to disable sandboxing that causes namespace errors with Python
[Service]
PrivateTmp=false
ProtectSystem=false
EOF

        log "Created override for: $SERVICE"
        ((FIXED++))
    fi
done

if [[ $FIXED -gt 0 ]]; then
    log "Fixed $FIXED services"
    log "Reloading systemd..."
    systemctl daemon-reload

    log "Restarting failed services..."
    systemctl reset-failed 'secubox-*' 2>/dev/null || true

    # Restart specifically known problematic services
    for svc in secubox-haproxy secubox-metrics secubox-threats; do
        if systemctl is-enabled "$svc" &>/dev/null; then
            log "Restarting $svc..."
            systemctl restart "$svc" 2>/dev/null || warn "$svc failed to start"
        fi
    done

    log "Done! Check status with: systemctl status 'secubox-*'"
else
    log "No services needed fixing"
fi
