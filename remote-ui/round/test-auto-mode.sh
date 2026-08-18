#!/bin/bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# ═══════════════════════════════════════════════════════════════════════════════
# SecuBox Eye Remote — Auto-Mode Test Script
# CyberMind — Gérald Kerma
#
# Tests all gadget modes on the Pi Zero W.
#
# Usage: test-auto-mode.sh [-h HOST]
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
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[test]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }
err()  { echo -e "${RED}[error]${NC} $*" >&2; }
info() { echo -e "${BLUE}[info]${NC} $*"; }
header() { echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════${NC}"; echo -e "${CYAN}$*${NC}"; echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"; }

# Default host (try OTG first via MOCHAbin)
MOCHA_HOST="192.168.1.200"
PI_HOST="10.55.0.2"
PI_USER="pi"
PI_PASS="raspberry"

usage() {
    cat << EOF
SecuBox Eye Remote — Auto-Mode Test Script v${VERSION}

Usage: $0 [OPTIONS]

Options:
  -m, --mocha HOST    MOCHAbin IP (default: $MOCHA_HOST)
  -p, --pi HOST       Pi Zero IP (default: $PI_HOST via MOCHAbin)
  -u, --user USER     Pi SSH user (default: $PI_USER)
  --help              Show this help

Tests:
  1. Network mode (ECM + ACM)
  2. HID mode (Keyboard + ACM)
  3. Storage mode (Mass Storage + ACM)
  4. Silent storage mode (Storage fallback)
  5. Mode switching
  6. Wake triggers

EOF
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -m|--mocha) MOCHA_HOST="$2"; shift 2 ;;
        -p|--pi)    PI_HOST="$2"; shift 2 ;;
        -u|--user)  PI_USER="$2"; shift 2 ;;
        --help)     usage ;;
        *)          err "Unknown option: $1"; exit 1 ;;
    esac
done

# SSH command helper (via MOCHAbin)
ssh_pi() {
    ssh -o StrictHostKeyChecking=no root@"$MOCHA_HOST" \
        "sshpass -p '$PI_PASS' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 ${PI_USER}@${PI_HOST} '$*'" 2>&1
}

# Direct SSH to MOCHAbin
ssh_mocha() {
    ssh -o StrictHostKeyChecking=no root@"$MOCHA_HOST" "$*" 2>&1
}

header "SecuBox Eye Remote — Auto-Mode Test Suite v${VERSION}"
log "MOCHAbin: $MOCHA_HOST"
log "Pi Zero:  $PI_HOST (via MOCHAbin)"
log ""

# ═══════════════════════════════════════════════════════════════════════════════
# Test 1: Connectivity
# ═══════════════════════════════════════════════════════════════════════════════

header "Test 1: Connectivity Check"

info "Checking MOCHAbin connectivity..."
if ssh_mocha "hostname" >/dev/null 2>&1; then
    log "✓ MOCHAbin reachable"
else
    err "✗ Cannot reach MOCHAbin at $MOCHA_HOST"
    exit 1
fi

info "Checking Pi Zero connectivity..."
if ssh_mocha "ping -c 1 -W 2 $PI_HOST" >/dev/null 2>&1; then
    log "✓ Pi Zero reachable via network"
else
    warn "✗ Pi Zero not reachable via network"
    info "Checking serial console..."
    if ssh_mocha "test -c /dev/ttyACM0" 2>/dev/null; then
        log "✓ Serial console available at /dev/ttyACM0"
    else
        err "✗ No connectivity to Pi Zero"
        exit 1
    fi
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Test 2: Current Gadget Status
# ═══════════════════════════════════════════════════════════════════════════════

header "Test 2: Current Gadget Status"

info "Checking USB gadget on MOCHAbin..."
ssh_mocha "lsusb | grep -i 'linux\|gadget\|1d6b'" || true

info "Checking network interfaces..."
ssh_mocha "ip addr show | grep -E '(eye-remote|enx02fb|usb)' -A 2" || true

info "Checking Pi gadget configuration..."
GADGET_STATUS=$(ssh_pi "cat /sys/kernel/config/usb_gadget/secubox/UDC 2>/dev/null || echo 'not-configured'") || GADGET_STATUS="error"
log "Gadget UDC: $GADGET_STATUS"

# ═══════════════════════════════════════════════════════════════════════════════
# Test 3: Network Mode
# ═══════════════════════════════════════════════════════════════════════════════

header "Test 3: Network Mode (ECM + ACM)"

info "Switching to network mode..."
ssh_pi "sudo /etc/secubox/eye-remote/gadget-setup.sh network" || warn "Mode switch command failed"

sleep 3
info "Verifying network connectivity..."
if ssh_mocha "ping -c 2 -W 2 $PI_HOST" >/dev/null 2>&1; then
    log "✓ Network mode: PASS"
else
    warn "✗ Network mode: FAIL (no ping response)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Test 4: HID Mode
# ═══════════════════════════════════════════════════════════════════════════════

header "Test 4: HID Mode (Keyboard + ACM)"

info "Switching to HID mode..."
ssh_pi "sudo /etc/secubox/eye-remote/gadget-setup.sh hid" || warn "Mode switch command failed"

sleep 3
info "Checking HID device..."
HID_DEV=$(ssh_pi "test -c /dev/hidg0 && echo 'present' || echo 'absent'") || HID_DEV="error"
if [[ "$HID_DEV" == "present" ]]; then
    log "✓ HID mode: PASS (/dev/hidg0 present)"

    info "Testing keystroke..."
    ssh_pi "sudo /usr/local/bin/setup-hid-gadget.sh test" 2>/dev/null || warn "Keystroke test skipped"
else
    warn "✗ HID mode: FAIL (/dev/hidg0 not present)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Test 5: Storage Mode
# ═══════════════════════════════════════════════════════════════════════════════

header "Test 5: Storage Mode (Mass Storage + ACM)"

info "Switching to storage mode..."
ssh_pi "sudo /etc/secubox/eye-remote/gadget-setup.sh storage" || warn "Mode switch command failed"

sleep 3
info "Checking mass storage on MOCHAbin..."
STORAGE_DEV=$(ssh_mocha "lsblk | grep -i 'file-stor\|gadget' || ls /dev/disk/by-id/*Gadget* 2>/dev/null" | head -1) || STORAGE_DEV=""
if [[ -n "$STORAGE_DEV" ]]; then
    log "✓ Storage mode: PASS"
    log "  Device: $STORAGE_DEV"
else
    warn "✗ Storage mode: FAIL (no storage device detected)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Test 6: Silent Storage Mode
# ═══════════════════════════════════════════════════════════════════════════════

header "Test 6: Silent Storage Mode (Fallback)"

info "Switching to silent storage mode..."
ssh_pi "sudo /etc/secubox/eye-remote/gadget-setup.sh silent-storage" || warn "Mode switch command failed"

sleep 3
info "Verifying silent mode..."
SILENT_STORAGE=$(ssh_mocha "lsblk | grep -i 'file-stor\|gadget' || ls /dev/disk/by-id/*Gadget* 2>/dev/null" | head -1) || SILENT_STORAGE=""
SERIAL_OK=$(ssh_mocha "test -c /dev/ttyACM0 && echo 'yes' || echo 'no'") || SERIAL_OK="no"

if [[ -n "$SILENT_STORAGE" && "$SERIAL_OK" == "yes" ]]; then
    log "✓ Silent storage mode: PASS"
    log "  Storage: present"
    log "  Serial console: available"
else
    warn "✗ Silent storage mode: partial"
    [[ -z "$SILENT_STORAGE" ]] && warn "  Storage: not detected"
    [[ "$SERIAL_OK" != "yes" ]] && warn "  Serial: not available"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Test 7: Return to Network Mode
# ═══════════════════════════════════════════════════════════════════════════════

header "Test 7: Return to Network Mode"

info "Switching back to network mode..."
ssh_pi "sudo /etc/secubox/eye-remote/gadget-setup.sh network" 2>/dev/null || {
    info "Using serial to switch mode..."
    ssh_mocha "echo 'sudo /etc/secubox/eye-remote/gadget-setup.sh network' > /dev/ttyACM0" || true
}

sleep 5
info "Verifying network restored..."
if ssh_mocha "ping -c 2 -W 2 $PI_HOST" >/dev/null 2>&1; then
    log "✓ Network mode restored: PASS"
else
    warn "✗ Network mode restore: FAIL"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════════════

header "Test Summary"
log "All mode tests completed."
log ""
log "To test auto-mode controller:"
log "  ssh $PI_USER@$PI_HOST 'sudo systemctl start secubox-auto-mode'"
log ""
log "To monitor mode changes:"
log "  ssh $PI_USER@$PI_HOST 'journalctl -u secubox-auto-mode -f'"
log ""
