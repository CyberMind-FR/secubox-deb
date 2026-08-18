#!/bin/bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# ═══════════════════════════════════════════════════════════════════════════════
# SecuBox Eye Remote — Auto-Mode Deployment Script
# CyberMind — Gérald Kerma
#
# Deploys the auto-mode controller and wakeup manager to the Pi Zero W.
#
# Usage: deploy-auto-mode.sh [-h HOST] [-u USER] [-p PORT]
#
# License: Proprietary / ANSSI CSPN candidate
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="1.0.0"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${GREEN}[deploy-auto-mode]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }
err()  { echo -e "${RED}[error]${NC} $*" >&2; }
info() { echo -e "${BLUE}[info]${NC} $*"; }

# Defaults - try OTG first, then WiFi
HOST=""
USER="secubox"
PORT=22

usage() {
    cat << EOF
SecuBox Eye Remote — Auto-Mode Deployment v${VERSION}

Usage: $0 [OPTIONS]

Options:
  -h, --host HOST     Target IP/hostname (default: auto-detect 10.55.0.2 or secubox-eye.local)
  -u, --user USER     SSH user (default: $USER)
  -p, --port PORT     SSH port (default: $PORT)
  --help              Show this help

Examples:
  $0                              # Auto-detect connection
  $0 -h 10.55.0.2                 # Use OTG IP
  $0 -h secubox-eye.local         # Use mDNS hostname
  $0 -h 192.168.1.42 -u pi        # Use WiFi IP

EOF
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--host)  HOST="$2"; shift 2 ;;
        -u|--user)  USER="$2"; shift 2 ;;
        -p|--port)  PORT="$2"; shift 2 ;;
        --help)     usage ;;
        *)          err "Unknown option: $1"; exit 1 ;;
    esac
done

# Auto-detect host if not specified
if [[ -z "$HOST" ]]; then
    log "Auto-detecting Pi Zero W connection..."

    # Try OTG first
    if ping -c 1 -W 2 10.55.0.2 &>/dev/null; then
        HOST="10.55.0.2"
        info "Found via OTG: $HOST"
    # Try mDNS
    elif avahi-resolve -n secubox-eye.local &>/dev/null; then
        HOST="secubox-eye.local"
        info "Found via mDNS: $HOST"
    elif avahi-resolve -n secubox-round.local &>/dev/null; then
        HOST="secubox-round.local"
        info "Found via mDNS: $HOST"
    else
        err "Could not detect Pi Zero W. Please specify with -h"
        err "Make sure the Pi is connected via USB OTG or WiFi"
        exit 1
    fi
fi

log "═══════════════════════════════════════════════════════════════"
log "SecuBox Eye Remote — Auto-Mode Deployment v$VERSION"
log "═══════════════════════════════════════════════════════════════"
log ""
log "Target: ${USER}@${HOST}:${PORT}"
log ""

# Test SSH connection
log "Testing SSH connection..."
if ! ssh -p "$PORT" -o ConnectTimeout=10 -o BatchMode=yes "${USER}@${HOST}" "echo ok" &>/dev/null; then
    err "Cannot connect to ${USER}@${HOST}:${PORT}"
    err "Check that:"
    err "  - Pi is powered on and connected"
    err "  - SSH is enabled"
    err "  - Your SSH key is authorized"
    exit 1
fi
log "SSH connection OK"

# Create target directories
log "Creating target directories..."
ssh -p "$PORT" "${USER}@${HOST}" << 'REMOTE_DIRS'
set -e
sudo mkdir -p /usr/lib/secubox/eye-remote/agent/api
sudo mkdir -p /usr/lib/secubox/eye-remote/agent/display
sudo mkdir -p /etc/secubox/eye-remote
sudo mkdir -p /etc/systemd/system
sudo mkdir -p /usr/local/bin
sudo chown -R secubox:secubox /usr/lib/secubox/eye-remote 2>/dev/null || true
REMOTE_DIRS

# Copy Python modules
log "Deploying Python modules..."

# Auto-mode controller
log "  → auto_mode_controller.py"
scp -P "$PORT" "$SCRIPT_DIR/agent/auto_mode_controller.py" \
    "${USER}@${HOST}:/tmp/auto_mode_controller.py"
ssh -p "$PORT" "${USER}@${HOST}" \
    "sudo mv /tmp/auto_mode_controller.py /usr/lib/secubox/eye-remote/agent/"

# Wakeup manager
log "  → wakeup_manager.py"
scp -P "$PORT" "$SCRIPT_DIR/agent/wakeup_manager.py" \
    "${USER}@${HOST}:/tmp/wakeup_manager.py"
ssh -p "$PORT" "${USER}@${HOST}" \
    "sudo mv /tmp/wakeup_manager.py /usr/lib/secubox/eye-remote/agent/"

# Gadget switcher API (updated)
log "  → api/gadget_switcher.py"
scp -P "$PORT" "$SCRIPT_DIR/agent/api/gadget_switcher.py" \
    "${USER}@${HOST}:/tmp/gadget_switcher.py"
ssh -p "$PORT" "${USER}@${HOST}" \
    "sudo mv /tmp/gadget_switcher.py /usr/lib/secubox/eye-remote/agent/api/"

# Failover (updated)
log "  → failover.py"
scp -P "$PORT" "$SCRIPT_DIR/agent/failover.py" \
    "${USER}@${HOST}:/tmp/failover.py"
ssh -p "$PORT" "${USER}@${HOST}" \
    "sudo mv /tmp/failover.py /usr/lib/secubox/eye-remote/agent/"

# Gadget status display (updated)
log "  → display/gadget_status.py"
scp -P "$PORT" "$SCRIPT_DIR/agent/display/gadget_status.py" \
    "${USER}@${HOST}:/tmp/gadget_status.py"
ssh -p "$PORT" "${USER}@${HOST}" \
    "sudo mv /tmp/gadget_status.py /usr/lib/secubox/eye-remote/agent/display/"

# Copy config files
log "Deploying configuration files..."

# Auto-mode config
log "  → auto-mode.toml"
scp -P "$PORT" "$SCRIPT_DIR/files/etc/secubox/eye-remote/auto-mode.toml" \
    "${USER}@${HOST}:/tmp/auto-mode.toml"
ssh -p "$PORT" "${USER}@${HOST}" \
    "sudo mv /tmp/auto-mode.toml /etc/secubox/eye-remote/"

# Gadget setup script (updated)
log "  → gadget-setup.sh"
scp -P "$PORT" "$SCRIPT_DIR/files/etc/secubox/eye-remote/gadget-setup.sh" \
    "${USER}@${HOST}:/tmp/gadget-setup.sh"
ssh -p "$PORT" "${USER}@${HOST}" << 'INSTALL_GADGET_SETUP'
set -e
sudo mv /tmp/gadget-setup.sh /etc/secubox/eye-remote/
sudo chmod +x /etc/secubox/eye-remote/gadget-setup.sh
INSTALL_GADGET_SETUP

# HID gadget setup script
log "  → setup-hid-gadget.sh"
scp -P "$PORT" "$SCRIPT_DIR/scripts/setup-hid-gadget.sh" \
    "${USER}@${HOST}:/tmp/setup-hid-gadget.sh"
ssh -p "$PORT" "${USER}@${HOST}" << 'INSTALL_HID_SETUP'
set -e
sudo mv /tmp/setup-hid-gadget.sh /usr/local/bin/
sudo chmod +x /usr/local/bin/setup-hid-gadget.sh
INSTALL_HID_SETUP

# Copy systemd service
log "Deploying systemd service..."
scp -P "$PORT" "$SCRIPT_DIR/files/etc/systemd/system/secubox-auto-mode.service" \
    "${USER}@${HOST}:/tmp/secubox-auto-mode.service"
ssh -p "$PORT" "${USER}@${HOST}" << 'INSTALL_SERVICE'
set -e
sudo mv /tmp/secubox-auto-mode.service /etc/systemd/system/
sudo systemctl daemon-reload
# Enable but don't start yet
sudo systemctl enable secubox-auto-mode.service
INSTALL_SERVICE

# Set permissions
log "Setting permissions..."
ssh -p "$PORT" "${USER}@${HOST}" << 'SET_PERMS'
set -e
sudo chown -R root:root /usr/lib/secubox/eye-remote/agent/
sudo chmod -R 644 /usr/lib/secubox/eye-remote/agent/*.py
sudo chmod 755 /usr/lib/secubox/eye-remote/agent/
sudo chmod 755 /usr/lib/secubox/eye-remote/agent/api/
sudo chmod 755 /usr/lib/secubox/eye-remote/agent/display/
sudo chown root:root /etc/secubox/eye-remote/*.toml
sudo chmod 644 /etc/secubox/eye-remote/*.toml
sudo chown root:root /etc/secubox/eye-remote/*.sh
sudo chmod 755 /etc/secubox/eye-remote/*.sh
SET_PERMS

# Summary
log ""
log "═══════════════════════════════════════════════════════════════"
log "Deployment complete!"
log "═══════════════════════════════════════════════════════════════"
log ""
log "Deployed files:"
log "  /usr/lib/secubox/eye-remote/agent/auto_mode_controller.py"
log "  /usr/lib/secubox/eye-remote/agent/wakeup_manager.py"
log "  /usr/lib/secubox/eye-remote/agent/api/gadget_switcher.py"
log "  /usr/lib/secubox/eye-remote/agent/failover.py"
log "  /usr/lib/secubox/eye-remote/agent/display/gadget_status.py"
log "  /etc/secubox/eye-remote/auto-mode.toml"
log "  /etc/secubox/eye-remote/gadget-setup.sh"
log "  /usr/local/bin/setup-hid-gadget.sh"
log "  /etc/systemd/system/secubox-auto-mode.service"
log ""
log "To start the auto-mode controller:"
log "  ssh ${USER}@${HOST} 'sudo systemctl start secubox-auto-mode'"
log ""
log "To test gadget modes:"
log "  $SCRIPT_DIR/test-auto-mode.sh -h ${HOST}"
log ""
