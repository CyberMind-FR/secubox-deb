#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# SecuBox Eye Remote :: fix-display-ssh.sh
# CyberMind — Gérald Kerma
#
# Fix HyperPixel 2.1 Round display issues via SSH
# Copies files and applies configuration remotely
#
# Usage: ./fix-display-ssh.sh [user@host]
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

RED='\033[0;31m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'
GOLD='\033[0;33m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${CYAN}[fix-display]${NC} $*"; }
ok()   { echo -e "${GREEN}[    OK     ]${NC} $*"; }
err()  { echo -e "${RED}[   FAIL    ]${NC} $*" >&2; exit 1; }
warn() { echo -e "${GOLD}[   WARN    ]${NC} $*"; }

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
    fi
fi

log "═══════════════════════════════════════════════════════════════"
log " SecuBox Eye Remote - Display Fix via SSH"
log "═══════════════════════════════════════════════════════════════"
log "Target: $HOST"
echo ""

# Step 1: Copy fb_dashboard.py
log "1/5 Copying fb_dashboard.py..."
if [[ -f "${SCRIPT_DIR}/fb_dashboard.py" ]]; then
    scp "${SCRIPT_DIR}/fb_dashboard.py" "${HOST}:/tmp/"
    ssh "$HOST" "sudo cp /tmp/fb_dashboard.py /usr/local/bin/ && sudo chmod +x /usr/local/bin/fb_dashboard.py"
    ok "Copied fb_dashboard.py"
else
    warn "fb_dashboard.py not found locally, skipping copy"
fi

# Step 2: Copy assets
log "2/5 Copying icon assets..."
if [[ -d "${SCRIPT_DIR}/assets/icons" ]]; then
    ssh "$HOST" "sudo mkdir -p /usr/local/bin/assets/icons"
    scp "${SCRIPT_DIR}/assets/icons/"*.png "${HOST}:/tmp/" 2>/dev/null || true
    ssh "$HOST" "sudo mv /tmp/*.png /usr/local/bin/assets/icons/ 2>/dev/null || true"
    ok "Copied icons"
else
    warn "Icons directory not found"
fi

# Step 3: Apply fixes remotely
log "3/5 Applying configuration fixes..."
ssh "$HOST" bash -s << 'REMOTE_FIX'
#!/bin/bash
set -euo pipefail

# Find boot partition
BOOT_DIR=""
if [[ -d /boot/firmware ]]; then
    BOOT_DIR="/boot/firmware"
elif [[ -d /boot ]]; then
    BOOT_DIR="/boot"
fi
CONFIG="$BOOT_DIR/config.txt"

NEEDS_REBOOT=0

echo "Checking config.txt ($CONFIG)..."

# Required entries for HyperPixel 2.1 Round
add_if_missing() {
    local entry="$1"
    if ! grep -q "^${entry}" "$CONFIG" 2>/dev/null; then
        echo "$entry" | sudo tee -a "$CONFIG" > /dev/null
        echo "  Added: $entry"
        NEEDS_REBOOT=1
    fi
}

# Core display settings
add_if_missing "gpu_mem=128"
add_if_missing "dtoverlay=vc4-kms-v3d"
add_if_missing "max_framebuffers=2"
add_if_missing "dtoverlay=vc4-kms-dpi-hyperpixel2r"

# USB gadget support
add_if_missing "dtoverlay=dwc2"

# Remove conflicting entries
if grep -q "^dtoverlay=vc4-fkms" "$CONFIG"; then
    sudo sed -i '/^dtoverlay=vc4-fkms/d' "$CONFIG"
    echo "  Removed: conflicting vc4-fkms overlay"
    NEEDS_REBOOT=1
fi

# Remove duplicate vc4-kms-v3d entries
count=$(grep -c "^dtoverlay=vc4-kms-v3d" "$CONFIG" 2>/dev/null || echo 0)
if [[ $count -gt 1 ]]; then
    # Keep only first occurrence
    sudo sed -i '0,/^dtoverlay=vc4-kms-v3d/{//!d}; /^dtoverlay=vc4-kms-v3d/!b; x; /./{x;d}; x; h' "$CONFIG" 2>/dev/null || true
    echo "  Fixed: duplicate vc4-kms-v3d entries"
    NEEDS_REBOOT=1
fi

# Install Python dependencies
echo "Checking Python dependencies..."
if ! python3 -c "from PIL import Image" 2>/dev/null; then
    echo "Installing Pillow..."
    sudo apt-get update -qq
    sudo apt-get install -y python3-pil fonts-dejavu-core 2>/dev/null || true
fi

if [[ $NEEDS_REBOOT -eq 1 ]]; then
    echo "REBOOT_REQUIRED"
fi
REMOTE_FIX

# Check if reboot is needed
REBOOT_NEEDED=$(ssh "$HOST" "cat /tmp/reboot_flag 2>/dev/null || echo 'no'")

# Step 4: Install/update systemd service
log "4/5 Installing systemd service..."
ssh "$HOST" bash -s << 'SERVICE_INSTALL'
cat > /tmp/secubox-fb-dashboard.service << 'SVCEOF'
[Unit]
Description=SecuBox Eye Remote Framebuffer Dashboard
After=multi-user.target systemd-udev-settle.service

[Service]
Type=simple
User=root
# Wait for framebuffer
ExecStartPre=/bin/sh -c "for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do [ -e /dev/fb0 ] && exit 0; sleep 1; done; echo 'fb0 timeout'"
# Disable VT console
ExecStartPre=-/bin/sh -c "echo 0 > /sys/class/vtconsole/vtcon1/bind 2>/dev/null || true"
ExecStart=/usr/bin/python3 /usr/local/bin/fb_dashboard.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF
sudo mv /tmp/secubox-fb-dashboard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable secubox-fb-dashboard
echo "Service installed"
SERVICE_INSTALL
ok "Service installed"

# Step 5: Test/restart service
log "5/5 Testing display..."
ssh "$HOST" bash -s << 'TEST_DISPLAY'
# Check if fb0 exists
if [[ -e /dev/fb0 ]]; then
    echo "Framebuffer: /dev/fb0 exists"

    # Try to restart the service
    sudo systemctl restart secubox-fb-dashboard
    sleep 3

    if systemctl is-active --quiet secubox-fb-dashboard; then
        echo "SERVICE_RUNNING"
    else
        echo "SERVICE_FAILED"
        journalctl -u secubox-fb-dashboard -n 5 --no-pager
    fi
else
    echo "NO_FRAMEBUFFER"
    echo "Current display devices:"
    ls -la /dev/fb* /dev/dri/* 2>/dev/null || echo "  None found"
fi
TEST_DISPLAY

# Collect result
RESULT=$(ssh "$HOST" "systemctl is-active secubox-fb-dashboard 2>/dev/null || echo 'inactive'")

echo ""
log "═══════════════════════════════════════════════════════════════"

if [[ "$RESULT" == "active" ]]; then
    echo -e "${GREEN}${BOLD}Display should be working!${NC}"
    echo ""
    echo "  Dashboard service is running."
    echo "  If display is still blank, a reboot may be required:"
    echo "    ssh $HOST 'sudo reboot'"
else
    FB_EXISTS=$(ssh "$HOST" "[[ -e /dev/fb0 ]] && echo 'yes' || echo 'no'")

    if [[ "$FB_EXISTS" == "no" ]]; then
        echo -e "${GOLD}${BOLD}REBOOT REQUIRED${NC}"
        echo ""
        echo "  The HyperPixel display overlay is not loaded."
        echo "  Run: ssh $HOST 'sudo reboot'"
        echo ""
        echo "  After reboot, check:"
        echo "    ssh $HOST 'ls /dev/fb0 && systemctl status secubox-fb-dashboard'"
    else
        echo -e "${RED}${BOLD}Service failed to start${NC}"
        echo ""
        echo "  Check logs: ssh $HOST 'journalctl -u secubox-fb-dashboard -f'"
        echo "  Manual test: ssh $HOST 'sudo python3 /usr/local/bin/fb_dashboard.py'"
    fi
fi

log "═══════════════════════════════════════════════════════════════"
