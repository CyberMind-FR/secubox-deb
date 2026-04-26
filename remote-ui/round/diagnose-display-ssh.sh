#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# SecuBox Eye Remote :: diagnose-display-ssh.sh
# CyberMind — Gérald Kerma
#
# Diagnose and fix HyperPixel 2.1 Round display issues via SSH
# Usage: ./diagnose-display-ssh.sh [user@host]
#
# Default host: pi@raspberrypi.local or pi@10.55.0.2 (OTG)
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[0;31m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'
GOLD='\033[0;33m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${CYAN}[diagnose]${NC} $*"; }
ok()   { echo -e "${GREEN}[    OK   ]${NC} $*"; }
err()  { echo -e "${RED}[  FAIL   ]${NC} $*"; }
warn() { echo -e "${GOLD}[  WARN   ]${NC} $*"; }

# Target host
HOST="${1:-}"

# Try to find the Pi
find_pi() {
    local hosts=(
        "pi@10.55.0.2"      # OTG
        "pi@raspberrypi.local"
        "pi@secubox-eye.local"
    )

    for h in "${hosts[@]}"; do
        log "Trying $h..."
        if ssh -o ConnectTimeout=3 -o BatchMode=yes "$h" 'exit 0' 2>/dev/null; then
            HOST="$h"
            ok "Found Pi at $h"
            return 0
        fi
    done
    return 1
}

if [[ -z "$HOST" ]]; then
    log "No host specified, scanning..."
    if ! find_pi; then
        err "Could not find Pi. Specify host: $0 pi@hostname"
        exit 1
    fi
fi

log "═══════════════════════════════════════════════════════════════"
log " SecuBox Eye Remote - Display Diagnostics"
log "═══════════════════════════════════════════════════════════════"
log "Target: $HOST"
echo ""

# Run diagnostic commands remotely
ssh -o ConnectTimeout=10 "$HOST" bash -s << 'REMOTE_SCRIPT'
#!/bin/bash
set -euo pipefail

RED='\033[0;31m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'
GOLD='\033[0;33m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${CYAN}[diag]${NC} $*"; }
ok()   { echo -e "${GREEN}[ OK ]${NC} $*"; }
err()  { echo -e "${RED}[FAIL]${NC} $*"; }
warn() { echo -e "${GOLD}[WARN]${NC} $*"; }

log "1/8 System Info"
echo "  Hostname: $(hostname)"
echo "  Kernel:   $(uname -r)"
echo "  Uptime:   $(uptime -p)"

# Find boot config
BOOT_DIR=""
if [[ -d /boot/firmware ]]; then
    BOOT_DIR="/boot/firmware"
elif [[ -d /boot ]]; then
    BOOT_DIR="/boot"
fi
CONFIG="$BOOT_DIR/config.txt"

log "2/8 Boot Config ($CONFIG)"
if [[ -f "$CONFIG" ]]; then
    echo "  Display-related entries:"
    grep -E "(dtoverlay|framebuf|gpu|fb|hyperpixel|dpi|vc4|hdmi)" "$CONFIG" 2>/dev/null | sed 's/^/  /'
else
    err "config.txt not found!"
fi

log "3/8 Framebuffer Devices"
if ls /dev/fb* 2>/dev/null; then
    for fb in /dev/fb*; do
        echo "  $fb:"
        if [[ -f /sys/class/graphics/$(basename $fb)/bits_per_pixel ]]; then
            echo "    bits_per_pixel: $(cat /sys/class/graphics/$(basename $fb)/bits_per_pixel)"
        fi
        if [[ -f /sys/class/graphics/$(basename $fb)/virtual_size ]]; then
            echo "    virtual_size:   $(cat /sys/class/graphics/$(basename $fb)/virtual_size)"
        fi
        if [[ -f /sys/class/graphics/$(basename $fb)/name ]]; then
            echo "    name:           $(cat /sys/class/graphics/$(basename $fb)/name)"
        fi
    done
    ok "Framebuffer devices found"
else
    err "No framebuffer devices!"
fi

log "4/8 DRM/KMS Devices"
if ls /dev/dri/* 2>/dev/null; then
    ls -la /dev/dri/ | sed 's/^/  /'
    ok "DRM devices found"
else
    warn "No DRM devices found"
fi

log "5/8 Display Modules"
echo "  Loaded modules:"
lsmod | grep -E "(vc4|drm|fb|gpu)" 2>/dev/null | sed 's/^/    /' || echo "    (none matching)"

log "6/8 Dashboard Service"
if systemctl is-active --quiet secubox-fb-dashboard 2>/dev/null; then
    ok "secubox-fb-dashboard is running"
    systemctl status secubox-fb-dashboard --no-pager 2>&1 | tail -5 | sed 's/^/  /'
else
    warn "secubox-fb-dashboard is not running"
    # Check if it exists
    if systemctl list-unit-files | grep -q secubox-fb-dashboard; then
        echo "  Service exists but not active"
        journalctl -u secubox-fb-dashboard --no-pager -n 10 2>&1 | sed 's/^/  /' || true
    else
        err "Service not installed"
    fi
fi

log "7/8 Python/Pillow Status"
if python3 -c "from PIL import Image; print('  Pillow OK')" 2>/dev/null; then
    ok "Pillow available"
else
    err "Pillow not installed!"
fi

log "8/8 fbset Output"
if command -v fbset &>/dev/null && [[ -e /dev/fb0 ]]; then
    fbset -fb /dev/fb0 2>&1 | sed 's/^/  /' || true
else
    warn "fbset not available or /dev/fb0 missing"
fi

echo ""
log "═══════════════════════════════════════════════════════════════"
log " Diagnosis Complete"
log "═══════════════════════════════════════════════════════════════"

# Determine fix needed
NEEDS_FIX=0

if [[ ! -e /dev/fb0 ]]; then
    err "CRITICAL: No framebuffer device - display overlay not loaded"
    NEEDS_FIX=1
fi

if ! grep -q "dtoverlay=vc4-kms-dpi-hyperpixel2r" "$CONFIG" 2>/dev/null; then
    warn "Missing HyperPixel overlay in config.txt"
    NEEDS_FIX=1
fi

if ! systemctl is-active --quiet secubox-fb-dashboard 2>/dev/null; then
    warn "Dashboard service not running"
    NEEDS_FIX=1
fi

if [[ $NEEDS_FIX -eq 1 ]]; then
    echo ""
    echo -e "${GOLD}${BOLD}Fixes needed! Run with --fix to apply:${NC}"
    echo "  $0 --fix"
fi
REMOTE_SCRIPT

echo ""
log "Local actions available:"
echo "  1. Apply fix:     $0 $HOST --fix"
echo "  2. View logs:     ssh $HOST 'journalctl -u secubox-fb-dashboard -f'"
echo "  3. Manual test:   ssh $HOST 'sudo python3 /usr/local/bin/fb_dashboard.py'"
