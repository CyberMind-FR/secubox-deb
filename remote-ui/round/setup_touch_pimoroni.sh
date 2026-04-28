#!/bin/bash
# ==============================================================================
# SecuBox Eye Remote - Setup Touch (Pimoroni Mode)
# Configure le HyperPixel 2r pour utiliser la bibliotheque Python Pimoroni
#
# Usage: sudo ./setup_touch_pimoroni.sh
#
# Ce script:
# 1. Modifie /boot/config.txt pour ajouter :disable-touch
# 2. Installe les dependances Python
# 3. Teste la connexion au controleur touch
#
# CyberMind - https://cybermind.fr
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[SETUP]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Check root
if [[ $EUID -ne 0 ]]; then
    err "Ce script doit etre execute en root (sudo)"
    exit 1
fi

# Detect config.txt location
CONFIG_TXT=""
for path in /boot/firmware/config.txt /boot/config.txt; do
    if [[ -f "$path" ]]; then
        CONFIG_TXT="$path"
        break
    fi
done

if [[ -z "$CONFIG_TXT" ]]; then
    err "config.txt non trouve"
    exit 1
fi

log "Configuration: $CONFIG_TXT"

# ==============================================================================
# Step 1: Backup config.txt
# ==============================================================================
log "Sauvegarde de config.txt..."
cp "$CONFIG_TXT" "${CONFIG_TXT}.bak.$(date +%Y%m%d%H%M%S)"

# ==============================================================================
# Step 2: Update HyperPixel overlay
# ==============================================================================
log "Mise a jour de l'overlay HyperPixel..."

if grep -q "dtoverlay=hyperpixel2r:disable-touch" "$CONFIG_TXT"; then
    log "Mode disable-touch deja configure"
elif grep -q "dtoverlay=hyperpixel2r" "$CONFIG_TXT"; then
    # Replace existing overlay with disable-touch version
    sed -i 's/dtoverlay=hyperpixel2r.*/dtoverlay=hyperpixel2r:disable-touch/' "$CONFIG_TXT"
    log "Overlay modifie: dtoverlay=hyperpixel2r:disable-touch"
else
    # Add new overlay
    echo "" >> "$CONFIG_TXT"
    echo "# HyperPixel 2r Round (touch via Python, not kernel)" >> "$CONFIG_TXT"
    echo "dtoverlay=hyperpixel2r:disable-touch" >> "$CONFIG_TXT"
    log "Overlay ajoute: dtoverlay=hyperpixel2r:disable-touch"
fi

# Ensure I2C is enabled
if ! grep -q "dtparam=i2c_arm=on" "$CONFIG_TXT"; then
    echo "dtparam=i2c_arm=on" >> "$CONFIG_TXT"
    log "I2C active"
fi

# ==============================================================================
# Step 3: Install Python dependencies
# ==============================================================================
log "Installation des dependances Python..."

# Install system packages
apt-get update -qq
apt-get install -y -qq python3-pip python3-smbus i2c-tools python3-rpi.gpio

# Install Python packages
pip3 install --break-system-packages hyperpixel2r smbus2 evdev 2>/dev/null || \
    pip3 install hyperpixel2r smbus2 evdev

log "Dependances installees"

# ==============================================================================
# Step 4: Add user to i2c group
# ==============================================================================
if id -nG "pi" 2>/dev/null | grep -qw "i2c"; then
    log "Utilisateur pi deja dans le groupe i2c"
else
    usermod -aG i2c pi 2>/dev/null || true
    log "Utilisateur pi ajoute au groupe i2c"
fi

# ==============================================================================
# Step 5: Test I2C (if bus 11 exists)
# ==============================================================================
if [[ -e /dev/i2c-11 ]]; then
    log "Test I2C bus 11..."
    if i2cdetect -y 11 2>/dev/null | grep -q "15"; then
        log "Controleur touch detecte sur bus 11, adresse 0x15"
    else
        warn "Controleur touch non detecte sur bus 11"
        warn "Redemarrez apres ce script"
    fi
else
    warn "Bus I2C 11 non disponible"
    warn "Il sera cree apres redemarrage avec le nouvel overlay"
fi

# ==============================================================================
# Step 6: Copy touch handler
# ==============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST_DIR="/opt/secubox-eye-remote"

if [[ -d "$SCRIPT_DIR/agent" ]]; then
    log "Installation du code Eye Remote..."
    mkdir -p "$DEST_DIR"
    cp -r "$SCRIPT_DIR/agent" "$DEST_DIR/"
    cp "$SCRIPT_DIR/requirements.txt" "$DEST_DIR/" 2>/dev/null || true
    cp "$SCRIPT_DIR/test_touch_i2c.py" "$DEST_DIR/" 2>/dev/null || true
    chown -R pi:pi "$DEST_DIR"
    log "Code installe dans $DEST_DIR"
fi

# ==============================================================================
# Done
# ==============================================================================
echo ""
echo "============================================================"
echo -e "${GREEN}Configuration terminee!${NC}"
echo "============================================================"
echo ""
echo "Changements effectues:"
echo "  - config.txt: dtoverlay=hyperpixel2r:disable-touch"
echo "  - Python: hyperpixel2r, smbus2, evdev installes"
echo "  - Groupe: pi ajoute a i2c"
echo ""
echo "IMPORTANT: Redemarrez le Pi Zero pour appliquer les changements:"
echo "  sudo reboot"
echo ""
echo "Apres redemarrage, testez avec:"
echo "  python3 /opt/secubox-eye-remote/test_touch_i2c.py"
echo ""
echo "Ou directement:"
echo "  python3 -c 'from hyperpixel2r import Touch; print(\"OK\")'"
echo ""
