#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# SecuBox Eye Remote - Display Fix Script
# Run this on the Pi Zero to fix the HyperPixel 2.1 Round display
# Usage: sudo bash fix-display.sh
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'; CYAN='\033[0;36m'; GREEN='\033[0;32m'
GOLD='\033[0;33m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${CYAN}[eye-fix]${NC} $*"; }
ok()   { echo -e "${GREEN}[  OK   ]${NC} $*"; }
err()  { echo -e "${RED}[ FAIL  ]${NC} $*" >&2; }
warn() { echo -e "${GOLD}[ WARN  ]${NC} $*"; }

[[ $EUID -ne 0 ]] && { err "Run as root: sudo bash $0"; exit 1; }

log "SecuBox Eye Remote Display Fix"
log "================================"

# ── Step 1: Check /boot/firmware/config.txt ─────────────────────────────────
log "1/6 Checking config.txt..."

BOOT_DIR=""
if [[ -d /boot/firmware ]]; then
    BOOT_DIR="/boot/firmware"
elif [[ -d /boot ]]; then
    BOOT_DIR="/boot"
fi

CONFIG="${BOOT_DIR}/config.txt"
NEEDS_REBOOT=0

if [[ ! -f "$CONFIG" ]]; then
    err "config.txt not found!"
    exit 1
fi

# Check for required overlays
check_add_overlay() {
    local overlay="$1"
    if ! grep -q "^dtoverlay=${overlay}" "$CONFIG"; then
        echo "dtoverlay=${overlay}" >> "$CONFIG"
        log "Added: dtoverlay=${overlay}"
        NEEDS_REBOOT=1
    else
        ok "dtoverlay=${overlay} present"
    fi
}

check_add_param() {
    local param="$1"
    if ! grep -q "^${param}" "$CONFIG"; then
        echo "${param}" >> "$CONFIG"
        log "Added: ${param}"
        NEEDS_REBOOT=1
    else
        ok "${param} present"
    fi
}

# Essential HyperPixel 2.1 Round configuration
check_add_overlay "vc4-kms-v3d"
check_add_param "max_framebuffers=2"
check_add_overlay "vc4-kms-dpi-hyperpixel2r"
check_add_overlay "dwc2"

# Also need I2C for touch (optional but useful)
check_add_param "dtparam=i2c_arm=on"

# Disable unnecessary overlays that cause conflicts
if grep -q "^dtoverlay=vc4-fkms" "$CONFIG"; then
    sed -i '/^dtoverlay=vc4-fkms/d' "$CONFIG"
    log "Removed conflicting vc4-fkms overlay"
    NEEDS_REBOOT=1
fi

# ── Step 2: Install Python dependencies ────────────────────────────────────
log "2/6 Installing Python dependencies..."

apt-get update -qq
apt-get install -y -qq python3-pip python3-pil fonts-dejavu-core 2>/dev/null || {
    warn "apt-get failed, trying pip install..."
}

pip3 install --break-system-packages pillow 2>/dev/null || pip3 install pillow 2>/dev/null || true
ok "Python dependencies"

# ── Step 3: Install fb_dashboard.py ────────────────────────────────────────
log "3/6 Installing fb_dashboard.py..."

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Check if fb_dashboard.py exists in script directory
if [[ -f "${SCRIPT_DIR}/fb_dashboard.py" ]]; then
    cp "${SCRIPT_DIR}/fb_dashboard.py" /usr/local/bin/
    chmod +x /usr/local/bin/fb_dashboard.py
    ok "Copied fb_dashboard.py from ${SCRIPT_DIR}"
elif [[ -f /opt/secubox/eye-remote/fb_dashboard.py ]]; then
    cp /opt/secubox/eye-remote/fb_dashboard.py /usr/local/bin/
    chmod +x /usr/local/bin/fb_dashboard.py
    ok "Copied fb_dashboard.py from /opt/secubox/eye-remote/"
else
    warn "fb_dashboard.py not found - you need to copy it manually to /usr/local/bin/"
fi

# ── Step 4: Install assets ─────────────────────────────────────────────────
log "4/6 Installing icon assets..."

mkdir -p /usr/local/bin/assets/icons

# Try to find and copy icons
ICON_SOURCES=(
    "${SCRIPT_DIR}/assets/icons"
    "/opt/secubox/eye-remote/assets/icons"
    "/home/pi/secubox/assets/icons"
)

ICONS_INSTALLED=0
for src in "${ICON_SOURCES[@]}"; do
    if [[ -d "$src" ]] && ls "$src"/*.png >/dev/null 2>&1; then
        cp "$src"/*.png /usr/local/bin/assets/icons/
        ICONS_INSTALLED=1
        ok "Copied icons from $src"
        break
    fi
done

if [[ $ICONS_INSTALLED -eq 0 ]]; then
    warn "Icon assets not found - dashboard will work without icons"
fi

# ── Step 5: Install systemd service ────────────────────────────────────────
log "5/6 Installing systemd service..."

cat > /etc/systemd/system/secubox-fb-dashboard.service << 'SVCEOF'
[Unit]
Description=SecuBox Eye Remote Framebuffer Dashboard
After=multi-user.target systemd-udev-settle.service

[Service]
Type=simple
User=root
# Wait for framebuffer device (up to 15s)
ExecStartPre=/bin/sh -c "for i in $(seq 1 15); do [ -e /dev/fb0 ] && exit 0; sleep 1; done; echo 'WARNING: /dev/fb0 not ready'"
# Disable console on framebuffer
ExecStartPre=-/bin/sh -c "echo 0 > /sys/class/vtconsole/vtcon1/bind 2>/dev/null || true"
ExecStart=/usr/bin/python3 /usr/local/bin/fb_dashboard.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable secubox-fb-dashboard.service
ok "systemd service installed and enabled"

# ── Step 6: Check framebuffer status ───────────────────────────────────────
log "6/6 Checking display status..."

echo ""
log "Framebuffer devices:"
ls -la /dev/fb* 2>/dev/null || warn "No framebuffer devices found!"

if [[ -e /dev/fb0 ]]; then
    ok "/dev/fb0 exists"

    # Show framebuffer info
    if [[ -f /sys/class/graphics/fb0/bits_per_pixel ]]; then
        BPP=$(cat /sys/class/graphics/fb0/bits_per_pixel)
        log "  bits_per_pixel: ${BPP}"
    fi
    if [[ -f /sys/class/graphics/fb0/virtual_size ]]; then
        VSIZE=$(cat /sys/class/graphics/fb0/virtual_size)
        log "  virtual_size: ${VSIZE}"
    fi

    # Try to start the service
    log "Starting dashboard service..."
    systemctl restart secubox-fb-dashboard.service
    sleep 3

    if systemctl is-active --quiet secubox-fb-dashboard.service; then
        ok "Dashboard service running!"
    else
        err "Dashboard service failed to start"
        log "Check logs with: journalctl -u secubox-fb-dashboard -f"
    fi
else
    warn "/dev/fb0 not found - display driver may not be loaded"
    warn "A reboot is required for the display overlay to take effect"
fi

# ── Summary ────────────────────────────────────────────────────────────────
echo ""
log "════════════════════════════════════════════════════════════════"
if [[ $NEEDS_REBOOT -eq 1 ]] || [[ ! -e /dev/fb0 ]]; then
    echo -e "${GOLD}${BOLD}REBOOT REQUIRED${NC}"
    echo ""
    echo "  Run: sudo reboot"
    echo ""
    echo "  After reboot, check status with:"
    echo "    systemctl status secubox-fb-dashboard"
    echo "    journalctl -u secubox-fb-dashboard -f"
else
    echo -e "${GREEN}${BOLD}Display should be working!${NC}"
    echo ""
    echo "  Check status with:"
    echo "    systemctl status secubox-fb-dashboard"
fi
log "════════════════════════════════════════════════════════════════"
