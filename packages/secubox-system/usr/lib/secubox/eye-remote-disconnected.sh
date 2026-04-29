#!/usr/bin/env bash
# SecuBox Eye Remote Disconnected Handler
# Called by udev when Pi Zero W Eye Remote is disconnected
# CyberMind - https://cybermind.fr
set -euo pipefail

IFACE="${INTERFACE:-eye-remote}"

log() {
    logger -t "secubox-eye-remote" "$*"
    echo "[eye-remote] $*"
}

log "Eye Remote disconnected: $IFACE"

# Notify SecuBox API
if command -v curl &>/dev/null; then
    curl -s -X POST "http://127.0.0.1:8000/api/v1/system/eye-remote/disconnected" \
        -H "Content-Type: application/json" \
        -d "{\"interface\": \"$IFACE\"}" \
        2>/dev/null || true
fi

log "Eye Remote cleanup complete"
