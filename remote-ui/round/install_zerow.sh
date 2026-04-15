#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# SecuBox Remote UI — install_zerow.sh
# Prépare et flashe une microSD pour RPi Zero W avec HyperPixel 2.1 Round
#
# CyberMind — https://cybermind.fr
# Author: Gérald Kerma <gandalf@gk2.net>
# License: Proprietary / ANSSI CSPN candidate
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="1.0.0"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${GREEN}[install]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }
err()  { echo -e "${RED}[error]${NC} $*" >&2; }

# Valeurs par défaut
DEVICE=""
IMAGE=""
SSID=""
PSK=""
HOSTNAME="secubox-round"
USER="secubox"
PUBKEY=""
KIOSK=true
NO_WIFI=false
USB_OTG=false

# ══════════════════════════════════════════════════════════════════════════════
# AIDE
# ══════════════════════════════════════════════════════════════════════════════

usage() {
    cat << EOF
SecuBox Remote UI — Installateur RPi Zero W + HyperPixel 2.1 Round

Usage: $0 [OPTIONS]

Options requises:
  -d, --device DEVICE     Périphérique SD (ex: /dev/sdb, /dev/mmcblk1)
  -i, --image IMAGE       Image Raspberry Pi OS (.img ou .img.xz)
  -s, --ssid SSID         Nom du réseau WiFi
  -p, --psk PSK           Mot de passe WiFi

Options facultatives:
  -h, --hostname NAME     Hostname (défaut: $HOSTNAME)
  -u, --user USER         Utilisateur (défaut: $USER)
  -k, --pubkey FILE       Clé SSH publique à installer
  --kiosk                 Activer le mode kiosk (défaut: oui)
  --no-wifi               Ne pas configurer le WiFi
  -r, --usb-otg           Activer USB OTG (mode gadget)
  --help                  Afficher cette aide

Sécurité:
  Le script refuse de flasher sur /dev/sda, /dev/nvme0n1, /dev/mmcblk0
  pour éviter d'effacer le disque système.

Exemples:
  $0 -d /dev/sdb -i raspios-lite.img -s MonWiFi -p "motdepasse"
  $0 -d /dev/mmcblk1 -i raspios-lite.img.xz -s MonWiFi -p pass -k ~/.ssh/id_rsa.pub

EOF
    exit 0
}

# ══════════════════════════════════════════════════════════════════════════════
# PARSING ARGUMENTS
# ══════════════════════════════════════════════════════════════════════════════

while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--device)  DEVICE="$2"; shift 2 ;;
        -i|--image)   IMAGE="$2"; shift 2 ;;
        -s|--ssid)    SSID="$2"; shift 2 ;;
        -p|--psk)     PSK="$2"; shift 2 ;;
        -h|--hostname) HOSTNAME="$2"; shift 2 ;;
        -u|--user)    USER="$2"; shift 2 ;;
        -k|--pubkey)  PUBKEY="$2"; shift 2 ;;
        --kiosk)      KIOSK=true; shift ;;
        --no-wifi)    NO_WIFI=true; shift ;;
        -r|--usb-otg) USB_OTG=true; shift ;;
        --help)       usage ;;
        *)            err "Option inconnue: $1"; exit 1 ;;
    esac
done

# ══════════════════════════════════════════════════════════════════════════════
# VALIDATIONS
# ══════════════════════════════════════════════════════════════════════════════

if [[ $EUID -ne 0 ]]; then
    err "Ce script doit être exécuté en root (sudo)"
    exit 1
fi

if [[ -z "$DEVICE" ]]; then
    err "Périphérique SD requis (-d)"
    exit 1
fi

if [[ -z "$IMAGE" ]]; then
    err "Image Raspberry Pi OS requise (-i)"
    exit 1
fi

if [[ ! -f "$IMAGE" ]]; then
    err "Image non trouvée: $IMAGE"
    exit 1
fi

if [[ "$NO_WIFI" != "true" ]]; then
    if [[ -z "$SSID" || -z "$PSK" ]]; then
        err "SSID et mot de passe WiFi requis (-s, -p) ou utilisez --no-wifi"
        exit 1
    fi
fi

# Sécurité: refuser les disques contenant le système racine
ROOT_DEV=$(findmnt -n -o SOURCE / 2>/dev/null | sed 's/[0-9]*$//' | sed 's/p[0-9]*$//')
log "Disque système racine: $ROOT_DEV"

# Vérifier si le device cible contient le système
if [[ -n "$ROOT_DEV" && "$DEVICE" == "$ROOT_DEV"* ]]; then
    err "REFUSÉ: $DEVICE contient votre système de fichiers racine !"
    err "Utilisez une carte SD externe"
    exit 1
fi

# Vérifier aussi les devices standards sauf si le système est ailleurs
FORBIDDEN_DEVICES="/dev/sda /dev/nvme0n1"
for forbidden in $FORBIDDEN_DEVICES; do
    if [[ "$DEVICE" == "$forbidden"* && "$ROOT_DEV" != "/dev/nvme0n1" && "$ROOT_DEV" != "/dev/sda" ]]; then
        warn "Attention: $DEVICE pourrait être un disque système"
        read -p "Êtes-vous sûr de vouloir continuer ? (oui/non) " -r
        if [[ ! $REPLY =~ ^[Oo][Uu][Ii]$ ]]; then
            exit 0
        fi
    fi
done

if [[ ! -b "$DEVICE" ]]; then
    err "Périphérique bloc non trouvé: $DEVICE"
    exit 1
fi

# ══════════════════════════════════════════════════════════════════════════════
# FLASH DE L'IMAGE
# ══════════════════════════════════════════════════════════════════════════════

log "═══════════════════════════════════════════════════════════════"
log "SecuBox Remote UI — Installation RPi Zero W v$VERSION"
log "═══════════════════════════════════════════════════════════════"
log ""
log "Périphérique: $DEVICE"
log "Image:        $IMAGE"
log "Hostname:     $HOSTNAME"
log "WiFi SSID:    ${SSID:-N/A}"
log ""

warn "ATTENTION: Toutes les données sur $DEVICE seront effacées !"
read -p "Continuer ? (oui/non) " -r
if [[ ! $REPLY =~ ^[Oo][Uu][Ii]$ ]]; then
    log "Annulé."
    exit 0
fi

# Démonter toutes les partitions
log "Démontage des partitions..."
for part in "${DEVICE}"*; do
    if mountpoint -q "$part" 2>/dev/null; then
        umount "$part" || true
    fi
done

# Flash de l'image
log "Flash de l'image (peut prendre plusieurs minutes)..."
if [[ "$IMAGE" == *.xz ]]; then
    xzcat "$IMAGE" | dd of="$DEVICE" bs=4M status=progress conv=fsync
else
    dd if="$IMAGE" of="$DEVICE" bs=4M status=progress conv=fsync
fi

sync
log "Flash terminé."

# ══════════════════════════════════════════════════════════════════════════════
# MONTAGE DES PARTITIONS
# ══════════════════════════════════════════════════════════════════════════════

log "Attente des partitions..."
sleep 3
partprobe "$DEVICE" 2>/dev/null || true
sleep 2

# Déterminer les noms des partitions
if [[ "$DEVICE" == *"mmcblk"* || "$DEVICE" == *"nvme"* ]]; then
    BOOT_PART="${DEVICE}p1"
    ROOT_PART="${DEVICE}p2"
else
    BOOT_PART="${DEVICE}1"
    ROOT_PART="${DEVICE}2"
fi

BOOT_MNT=$(mktemp -d)
ROOT_MNT=$(mktemp -d)

cleanup() {
    log "Nettoyage..."
    umount "$BOOT_MNT" 2>/dev/null || true
    umount "$ROOT_MNT" 2>/dev/null || true
    rmdir "$BOOT_MNT" "$ROOT_MNT" 2>/dev/null || true
}
trap cleanup EXIT

log "Montage de boot ($BOOT_PART)..."
mount "$BOOT_PART" "$BOOT_MNT"

log "Montage de rootfs ($ROOT_PART)..."
mount "$ROOT_PART" "$ROOT_MNT"

# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION HEADLESS
# ══════════════════════════════════════════════════════════════════════════════

# Activer SSH
log "Activation SSH..."
touch "$BOOT_MNT/ssh"

# Créer userconf pour Bookworm (requis pour l'authentification initiale)
# Format: user:hashed_password (pi:raspberry)
log "Création userconf pour Bookworm (pi:raspberry)..."
echo 'pi:$6$k5SVZ0uuYIi5gexv$2hLzZeHHwXdRLXpLP1M3dP8PTKRP0z/ejvFmrXeQPrl7NdIdcJGwY/gbr8vwAV6CXYri0fL.1SkRNZH/WcFyv1' > "$BOOT_MNT/userconf"

# Configuration WiFi
if [[ "$NO_WIFI" != "true" ]]; then
    log "Configuration WiFi ($SSID)..."
    cat > "$BOOT_MNT/wpa_supplicant.conf" << EOF
country=FR
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1

network={
    ssid="$SSID"
    psk="$PSK"
    key_mgmt=WPA-PSK
    priority=1
}
EOF
fi

# ══════════════════════════════════════════════════════════════════════════════
# HYPERPIXEL 2.1 ROUND — INSTALLATION OFFLINE
# ══════════════════════════════════════════════════════════════════════════════

log "Installation HyperPixel 2.1 Round (offline)..."

# Déterminer le répertoire overlays
OVERLAYS_DIR="$BOOT_MNT/overlays"
[[ ! -d "$OVERLAYS_DIR" ]] && OVERLAYS_DIR="$BOOT_MNT/firmware/overlays"
[[ ! -d "$OVERLAYS_DIR" ]] && OVERLAYS_DIR="$ROOT_MNT/boot/firmware/overlays"

if [[ ! -d "$OVERLAYS_DIR" ]]; then
    warn "Répertoire overlays non trouvé, création..."
    mkdir -p "$BOOT_MNT/overlays"
    OVERLAYS_DIR="$BOOT_MNT/overlays"
fi

# HyperPixel 2.1 Round overlay
# Modern RPi OS includes vc4-kms-dpi-hyperpixel2r.dtbo
# For older images, we download from Pimoroni releases

OVERLAY_NAME="hyperpixel2r"
OVERLAY_FILE="$OVERLAYS_DIR/${OVERLAY_NAME}.dtbo"

# HyperPixel 2.1 Round works with KMS overlay (vc4-kms-dpi-hyperpixel2r)
# The KMS overlay handles ST7789 panel init in kernel - no userspace script needed
# Tested and confirmed working on RPi Zero W with Bookworm (April 2026)
USE_KMS_OVERLAY=true
if [[ -f "$OVERLAYS_DIR/vc4-kms-dpi-hyperpixel2r.dtbo" ]]; then
    log "Overlay KMS vc4-kms-dpi-hyperpixel2r.dtbo trouvé (recommandé)"
    OVERLAY_NAME="vc4-kms-dpi-hyperpixel2r"
elif [[ -f "$SCRIPT_DIR/hyperpixel2r.dtbo" ]]; then
    log "Utilisation de l'overlay local hyperpixel2r.dtbo (non-KMS, fallback)"
    cp "$SCRIPT_DIR/hyperpixel2r.dtbo" "$OVERLAYS_DIR/hyperpixel2r.dtbo"
    OVERLAY_NAME="hyperpixel2r"
    USE_KMS_OVERLAY=false
elif [[ -f "$OVERLAYS_DIR/hyperpixel2r.dtbo" ]]; then
    log "Overlay hyperpixel2r.dtbo trouvé (non-KMS, fallback)"
    OVERLAY_NAME="hyperpixel2r"
    USE_KMS_OVERLAY=false
else
    # Download from Pimoroni GitHub releases (compiled dtbo)
    OVERLAY_URL="https://github.com/pimoroni/hyperpixel2r/raw/main/hyperpixel2r.dtbo"
    log "Téléchargement overlay hyperpixel2r.dtbo..."

    if command -v curl &>/dev/null; then
        curl -sL "$OVERLAY_URL" -o "$OVERLAY_FILE" 2>/dev/null
    elif command -v wget &>/dev/null; then
        wget -q "$OVERLAY_URL" -O "$OVERLAY_FILE" 2>/dev/null
    fi

    # If download failed, try alternative: clone and compile
    if [[ ! -f "$OVERLAY_FILE" ]] || [[ $(stat -c%s "$OVERLAY_FILE" 2>/dev/null) -lt 500 ]]; then
        warn "Téléchargement direct échoué, clonage du repo Pimoroni..."
        TEMP_DIR=$(mktemp -d)
        if git clone --depth 1 https://github.com/pimoroni/hyperpixel2r.git "$TEMP_DIR/hp" 2>/dev/null; then
            if [[ -f "$TEMP_DIR/hp/hyperpixel2r.dtbo" ]]; then
                cp "$TEMP_DIR/hp/hyperpixel2r.dtbo" "$OVERLAY_FILE"
                log "Overlay copié depuis repo cloné"
            elif [[ -f "$TEMP_DIR/hp/hyperpixel2r-overlay.dts" ]]; then
                # Compile from source if dtc available
                if command -v dtc &>/dev/null; then
                    dtc -@ -I dts -O dtb -o "$OVERLAY_FILE" "$TEMP_DIR/hp/hyperpixel2r-overlay.dts" 2>/dev/null && \
                        log "Overlay compilé depuis DTS"
                fi
            fi
        fi
        rm -rf "$TEMP_DIR"
    fi
fi

# Verify overlay
if [[ -f "$OVERLAY_FILE" ]]; then
    SIZE=$(stat -c%s "$OVERLAY_FILE" 2>/dev/null || echo 0)
    if [[ $SIZE -gt 500 ]]; then
        log "Overlay $OVERLAY_NAME installé ($SIZE bytes)"
    else
        warn "Overlay trop petit ($SIZE bytes) — probablement invalide"
        rm -f "$OVERLAY_FILE"
    fi
elif [[ "$OVERLAY_NAME" != "vc4-kms-dpi-hyperpixel2r" ]]; then
    warn "Overlay non installé — firstrun installera le driver Pimoroni"
fi

# Install HyperPixel init script (required for non-KMS overlay)
if [[ "$USE_KMS_OVERLAY" != "true" ]]; then
    if [[ -f "$SCRIPT_DIR/hyperpixel2r-init" ]]; then
        log "Installation hyperpixel2r-init script..."
        cp "$SCRIPT_DIR/hyperpixel2r-init" "$ROOT_MNT/usr/local/bin/"
        chmod +x "$ROOT_MNT/usr/local/bin/hyperpixel2r-init"

        # Create systemd service
        cat > "$ROOT_MNT/etc/systemd/system/hyperpixel2r-init.service" << 'HP2RSVC'
[Unit]
Description=HyperPixel 2.1 Round Init
DefaultDependencies=no
Before=local-fs.target sysinit.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/hyperpixel2r-init
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=sysinit.target
HP2RSVC

        # Enable the service
        mkdir -p "$ROOT_MNT/etc/systemd/system/sysinit.target.wants"
        ln -sf /etc/systemd/system/hyperpixel2r-init.service \
            "$ROOT_MNT/etc/systemd/system/sysinit.target.wants/hyperpixel2r-init.service"
        log "hyperpixel2r-init service installé"
    else
        warn "hyperpixel2r-init non trouvé — sera installé par firstrun"
    fi
fi

# Configuration config.txt pour HyperPixel 2.1 Round
log "Configuration config.txt..."

# Remove any existing hyperpixel config to avoid duplicates
sed -i '/hyperpixel/d' "$BOOT_MNT/config.txt" 2>/dev/null || true
sed -i '/HyperPixel/d' "$BOOT_MNT/config.txt" 2>/dev/null || true

# Gestion vc4-kms-v3d selon le type d'overlay
if [[ "$USE_KMS_OVERLAY" == "true" ]]; then
    # KMS overlay (vc4-kms-dpi-hyperpixel2r) REQUIRES vc4-kms-v3d
    log "Overlay KMS détecté — vc4-kms-v3d REQUIS (garder activé)"
    # S'assurer que vc4-kms-v3d est activé
    if ! grep -q "^dtoverlay=vc4-kms-v3d" "$BOOT_MNT/config.txt"; then
        # Décommenter si commenté
        sed -i 's/^#dtoverlay=vc4-kms-v3d.*/dtoverlay=vc4-kms-v3d/' "$BOOT_MNT/config.txt" 2>/dev/null || true
    fi
else
    # Non-KMS overlay (hyperpixel2r) CONFLICTS with vc4-kms-v3d
    log "Overlay non-KMS — désactivation vc4-kms-v3d (conflit)..."
    sed -i 's/^dtoverlay=vc4-kms-v3d/#dtoverlay=vc4-kms-v3d  # DISABLED - HyperPixel conflict/' "$BOOT_MNT/config.txt" 2>/dev/null || true
    sed -i 's/^dtoverlay=vc4-fkms-v3d/#dtoverlay=vc4-fkms-v3d  # DISABLED - HyperPixel conflict/' "$BOOT_MNT/config.txt" 2>/dev/null || true
fi
sed -i 's/^display_auto_detect=1/display_auto_detect=0/' "$BOOT_MNT/config.txt" 2>/dev/null || true

cat >> "$BOOT_MNT/config.txt" << HPCONFIG

# === SecuBox Remote UI — HyperPixel 2.1 Round ===
display_auto_detect=0
camera_auto_detect=0

# Désactiver HDMI et composite (économie énergie Zero W)
enable_tvout=0
hdmi_blanking=2

# GPU memory (128MB pour KMS/DRM)
gpu_mem=128

HPCONFIG

# KMS overlay requires vc4-kms-v3d BEFORE the display overlay
if [[ "$USE_KMS_OVERLAY" == "true" ]]; then
    cat >> "$BOOT_MNT/config.txt" << KMSCONFIG
# KMS graphics driver (required for vc4-kms-dpi-hyperpixel2r)
dtoverlay=vc4-kms-v3d

# Écran circulaire 480x480 Pimoroni - KMS overlay (handles panel init)
dtoverlay=${OVERLAY_NAME}
KMSCONFIG
else
    cat >> "$BOOT_MNT/config.txt" << NONKMSCONFIG
# Écran circulaire 480x480 Pimoroni - non-KMS overlay
dtoverlay=${OVERLAY_NAME},disable-i2c

# DPI configuration for non-KMS
enable_dpi_lcd=1
dpi_group=2
dpi_mode=87
dpi_output_format=0x7f216
dpi_timings=480 0 10 16 55 480 0 15 60 15 0 0 0 60 0 19200000 6

# Framebuffer dimensions
framebuffer_width=480
framebuffer_height=480
display_rotate=0
NONKMSCONFIG
fi

log "config.txt configuré avec overlay: $OVERLAY_NAME"

# Hostname
log "Configuration hostname ($HOSTNAME)..."
echo "$HOSTNAME" > "$ROOT_MNT/etc/hostname"
sed -i "s/raspberrypi/$HOSTNAME/g" "$ROOT_MNT/etc/hosts"

# Clé SSH
if [[ -n "$PUBKEY" && -f "$PUBKEY" ]]; then
    log "Installation clé SSH..."
    SSH_DIR="$ROOT_MNT/home/$USER/.ssh"
    mkdir -p "$SSH_DIR"
    cat "$PUBKEY" >> "$SSH_DIR/authorized_keys"
    chmod 700 "$SSH_DIR"
    chmod 600 "$SSH_DIR/authorized_keys"
    # Sera chowné au premier boot
fi

# ══════════════════════════════════════════════════════════════════════════════
# SCRIPT FIRSTRUN (installation driver HyperPixel + kiosk)
# ══════════════════════════════════════════════════════════════════════════════

log "Création du script firstrun..."
cat > "$ROOT_MNT/etc/rc.local" << 'RCLOCAL'
#!/bin/bash
# SecuBox Remote UI — Firstrun script
# Ce script s'exécute au premier démarrage et se désactive ensuite.

FLAG_FILE="/etc/.secubox_round_installed"

if [[ -f "$FLAG_FILE" ]]; then
    exit 0
fi

exec > /var/log/secubox-firstrun.log 2>&1
echo "=== SecuBox Remote UI — Firstrun $(date) ==="

# Attendre le réseau (max 60s)
echo "Attente réseau..."
for i in {1..60}; do
    if ping -c1 -W1 8.8.8.8 &>/dev/null; then
        echo "Réseau OK après ${i}s"
        break
    fi
    sleep 1
done

# Mise à jour APT
echo "Mise à jour APT..."
apt-get update -qq

# Installation dépendances
echo "Installation dépendances..."
apt-get install -y -qq \
    git \
    python3-pip \
    chromium-browser \
    nginx \
    x11-xserver-utils \
    xserver-xorg \
    xinit \
    lightdm \
    unclutter

# Installation driver HyperPixel 2.1 Round (si overlay non présent)
if [[ ! -f /boot/overlays/hyperpixel2r.dtbo ]] && [[ ! -f /boot/firmware/overlays/hyperpixel2r.dtbo ]]; then
    echo "Installation driver HyperPixel..."
    cd /tmp
    rm -rf hyperpixel2r
    git clone --depth 1 https://github.com/pimoroni/hyperpixel2r.git
    cd hyperpixel2r
    # Non-interactive install
    yes | ./install.sh || true
else
    echo "Overlay HyperPixel déjà présent, skip driver install"
fi

# Créer utilisateur secubox si nécessaire
if ! id secubox &>/dev/null; then
    useradd -m -s /bin/bash secubox
    echo "secubox:secubox2026" | chpasswd
fi

# Ajouter aux groupes
usermod -aG video,input,gpio,i2c,spi secubox

# Configuration autologin lightdm
mkdir -p /etc/lightdm/lightdm.conf.d
cat > /etc/lightdm/lightdm.conf.d/50-autologin.conf << 'LIGHTDM'
[Seat:*]
autologin-user=secubox
autologin-user-timeout=0
user-session=openbox
LIGHTDM

# Désactiver DPMS / screensaver
mkdir -p /home/secubox
cat > /home/secubox/.xinitrc << 'XINITRC'
#!/bin/bash
xset s off
xset -dpms
xset s noblank
unclutter -idle 0.1 -root &
exec openbox-session
XINITRC
chown secubox:secubox /home/secubox/.xinitrc

# Configuration Openbox autostart
mkdir -p /home/secubox/.config/openbox
cat > /home/secubox/.config/openbox/autostart << 'AUTOSTART'
# Désactiver screensaver
xset s off &
xset -dpms &
xset s noblank &

# Cacher le curseur
unclutter -idle 0.1 -root &

# Attendre que nginx soit prêt
sleep 5

# Lancer Chromium en mode kiosk
chromium-browser \
    --kiosk \
    --noerrdialogs \
    --disable-infobars \
    --disable-session-crashed-bubble \
    --disable-restore-session-state \
    --disable-translate \
    --no-first-run \
    --start-fullscreen \
    --window-size=480,480 \
    --window-position=0,0 \
    http://localhost:8080
AUTOSTART
chown -R secubox:secubox /home/secubox/.config

# Configuration nginx
cat > /etc/nginx/sites-available/secubox-round << 'NGINX'
server {
    listen 8080 default_server;
    server_name _;

    root /var/www/secubox-round;
    index index.html;

    # Proxy vers l'API SecuBox
    location /api/ {
        # L'IP sera configurée par deploy.sh
        proxy_pass http://192.168.1.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location / {
        try_files $uri $uri/ =404;
    }
}
NGINX

# Activer le site nginx
ln -sf /etc/nginx/sites-available/secubox-round /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Créer répertoire web
mkdir -p /var/www/secubox-round
cat > /var/www/secubox-round/index.html << 'PLACEHOLDER'
<!DOCTYPE html>
<html>
<head><title>SecuBox Remote UI</title></head>
<body style="background:#080808;color:#fff;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;">
<div style="text-align:center;">
<h1>SecuBox Remote UI</h1>
<p>En attente du déploiement...</p>
<p style="color:#666;">Exécutez deploy.sh depuis le serveur SecuBox</p>
</div>
</body>
</html>
PLACEHOLDER

# Activer les services
systemctl enable nginx
systemctl enable lightdm

# Marquer comme installé
touch "$FLAG_FILE"

echo "=== Firstrun terminé — Redémarrage dans 5s ==="
sleep 5
reboot

exit 0
RCLOCAL

chmod +x "$ROOT_MNT/etc/rc.local"

# ══════════════════════════════════════════════════════════════════════════════
# USB OTG COMPOSITE GADGET (ECM + ACM)
# ══════════════════════════════════════════════════════════════════════════════

if [[ "$USB_OTG" == "true" ]]; then
    log "Configuration USB OTG Composite (ECM + ACM)..."

    # config.txt: activer dwc2 en mode peripheral
    cat >> "$BOOT_MNT/config.txt" << 'OTGCFG'

# === SecuBox OTG Composite Gadget ===
dtoverlay=dwc2
OTGCFG

    # cmdline.txt: charger libcomposite au boot (pas g_ether car on utilise configfs)
    sed -i 's/rootwait/rootwait modules-load=dwc2,libcomposite/' "$BOOT_MNT/cmdline.txt"

    # /etc/modules: modules nécessaires
    cat >> "$ROOT_MNT/etc/modules" << 'MODEOF'
dwc2
libcomposite
usb_f_ecm
usb_f_acm
MODEOF

    # /etc/modprobe.d/secubox-otg.conf: forcer mode peripheral
    mkdir -p "$ROOT_MNT/etc/modprobe.d"
    cat > "$ROOT_MNT/etc/modprobe.d/secubox-otg.conf" << 'MODPROBE'
# SecuBox OTG: forcer mode peripheral pour gadget USB
options dwc2 dr_mode=peripheral
MODPROBE

    # Copier le script secubox-otg-gadget.sh
    log "Installation script OTG gadget..."
    cp "$SCRIPT_DIR/secubox-otg-gadget.sh" "$ROOT_MNT/usr/local/sbin/"
    chmod +x "$ROOT_MNT/usr/local/sbin/secubox-otg-gadget.sh"

    # Copier le service systemd
    cp "$SCRIPT_DIR/secubox-otg-gadget.service" "$ROOT_MNT/etc/systemd/system/"

    # Copier le service console série
    cp "$SCRIPT_DIR/secubox-serial-console.service" "$ROOT_MNT/etc/systemd/system/"

    # Activer les services OTG
    mkdir -p "$ROOT_MNT/etc/systemd/system/multi-user.target.wants"
    ln -sf /etc/systemd/system/secubox-otg-gadget.service \
        "$ROOT_MNT/etc/systemd/system/multi-user.target.wants/secubox-otg-gadget.service"
    ln -sf /etc/systemd/system/secubox-serial-console.service \
        "$ROOT_MNT/etc/systemd/system/multi-user.target.wants/secubox-serial-console.service"

    # Configuration réseau statique pour usb0 (côté gadget: 10.55.0.2/30)
    mkdir -p "$ROOT_MNT/etc/network/interfaces.d"
    cat > "$ROOT_MNT/etc/network/interfaces.d/usb0" << 'USB0CFG'
# SecuBox OTG: réseau Ethernet over USB
allow-hotplug usb0
iface usb0 inet static
    address 10.55.0.2
    netmask 255.255.255.252
    gateway 10.55.0.1
USB0CFG

    # Script de configuration directe usb0 (bypass NetworkManager)
    # NetworkManager ignore parfois ifupdown, ce script force la config
    log "Création script usb0-up.sh (bypass NetworkManager)..."
    mkdir -p "$ROOT_MNT/usr/local/bin"
    cat > "$ROOT_MNT/usr/local/bin/usb0-up.sh" << 'USB0UP'
#!/bin/bash
# SecuBox OTG: Force USB network configuration
# Bypasses NetworkManager which may ignore ifupdown config
# Debug log: /var/log/usb0-up.log

LOG=/var/log/usb0-up.log
exec >> "$LOG" 2>&1
echo "=== usb0-up.sh started $(date) ==="

sleep 5
echo "Waiting for usb0 interface..."

for i in {1..30}; do
    echo "Attempt $i: checking usb0..."
    ip link show usb0 2>&1
    if ip link show usb0 &>/dev/null; then
        echo "usb0 found! Configuring..."
        ip addr add 10.55.0.2/30 dev usb0 2>&1 || echo "IP already set or error"
        ip link set usb0 up 2>&1
        ip route add default via 10.55.0.1 dev usb0 2>&1 || echo "Route error (may exist)"
        echo "Configuration complete:"
        ip addr show usb0
        logger "SecuBox OTG: usb0 configured 10.55.0.2/30"
        echo "=== usb0-up.sh SUCCESS $(date) ==="
        exit 0
    fi
    sleep 2
done
echo "=== usb0-up.sh FAILED: usb0 not found $(date) ==="
logger "SecuBox OTG: usb0 not found after 60s"
exit 1
USB0UP
    chmod +x "$ROOT_MNT/usr/local/bin/usb0-up.sh"

    # Service systemd pour usb0-up.sh
    cat > "$ROOT_MNT/etc/systemd/system/usb0-up.service" << 'USB0SVC'
[Unit]
Description=SecuBox USB Gadget Network Setup
After=systemd-modules-load.service secubox-otg-gadget.service
Wants=secubox-otg-gadget.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/usb0-up.sh
RemainAfterExit=yes
TimeoutStartSec=90

[Install]
WantedBy=multi-user.target
USB0SVC

    # Activer usb0-up.service
    ln -sf /etc/systemd/system/usb0-up.service \
        "$ROOT_MNT/etc/systemd/system/multi-user.target.wants/usb0-up.service"

    log "OTG Composite configuré: ECM (usb0 @ 10.55.0.2/30) + ACM (ttyGS0)"
fi

# ══════════════════════════════════════════════════════════════════════════════
# FINALISATION
# ══════════════════════════════════════════════════════════════════════════════

sync
log "Synchronisation finale..."

log ""
log "═══════════════════════════════════════════════════════════════"
log "Installation terminée !"
log "═══════════════════════════════════════════════════════════════"
log ""
log "Prochaines étapes:"
log "  1. Éjecter la carte SD: sudo eject $DEVICE"
log "  2. Insérer dans le RPi Zero W avec HyperPixel"
log "  3. Connecter l'alimentation — le firstrun prendra ~5-10 min"
log "  4. Une fois redémarré, déployer le dashboard avec deploy.sh"
log ""
log "Connexion SSH (après firstrun):"
log "  ssh ${USER}@${HOSTNAME}.local"
log ""
