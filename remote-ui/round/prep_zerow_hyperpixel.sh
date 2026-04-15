#!/usr/bin/env bash
# ============================================================
#  prep_zerow_hyperpixel.sh
#  Préparation d'une microSD / clé USB pour :
#    Raspberry Pi Zero W + HyperPixel 2.1 Round Touch
#
#  Usage : sudo ./prep_zerow_hyperpixel.sh [OPTIONS]
#
#  Options :
#    -d DEVICE       Périphérique cible (ex: /dev/sdb)   [obligatoire]
#    -i IMAGE        Chemin vers l'image .img             [obligatoire]
#    -s SSID         Nom du réseau WiFi
#    -p PSK          Mot de passe WiFi
#    -h HOSTNAME     Nom d'hôte (défaut: rpi-zero-round)
#    -u USER         Nom d'utilisateur (défaut: pi)
#    -k PUBKEY       Chemin vers clé SSH publique (~/.ssh/id_rsa.pub)
#    -r              Activer USB boot OTP (IRRÉVERSIBLE, Zero W uniquement)
#    --kiosk         Installer mode kiosk Chromium au 1er boot
#    --no-wifi       Ne pas configurer le WiFi (câble USB/OTG)
#    --help          Afficher cette aide
#
#  Prérequis : dd, parted, e2fsck, mount, rsync (Linux uniquement)
#  Testé sur : Debian bookworm / Ubuntu 22.04 host
# ============================================================

set -euo pipefail

# ── Couleurs ────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
step()    { echo -e "\n${BOLD}${BLUE}━━ $* ${NC}"; }

# ── Valeurs par défaut ──────────────────────────────────────
DEVICE=""
IMAGE=""
WIFI_SSID=""
WIFI_PSK=""
HOSTNAME="rpi-zero-round"
USERNAME="pi"
PUBKEY=""
USB_OTP=false
KIOSK=false
NO_WIFI=false

BOOT_MNT="/tmp/rpi_boot_$$"
ROOT_MNT="/tmp/rpi_root_$$"

# ── Aide ────────────────────────────────────────────────────
usage() {
cat << EOF
${BOLD}Usage:${NC} sudo $0 -d /dev/sdX -i image.img [options]

  -d DEVICE    Périphérique cible  (ex: /dev/sdb)
  -i IMAGE     Image Raspberry Pi OS (.img ou .img.xz)
  -s SSID      SSID WiFi
  -p PSK       Mot de passe WiFi
  -h HOSTNAME  Nom d'hôte (défaut: rpi-zero-round)
  -u USER      Utilisateur (défaut: pi)
  -k PUBKEY    Clé SSH publique à autoriser
  -r           Activer USB OTP boot (IRRÉVERSIBLE)
  --kiosk      Préparer mode kiosk au 1er boot
  --no-wifi    Ne pas écrire wpa_supplicant
  --help       Afficher cette aide

${YELLOW}Exemple:${NC}
  sudo $0 -d /dev/sdb -i 2024-11-19-raspios-bookworm-armhf-lite.img \\
         -s MonWifi -p MotDePasse -k ~/.ssh/id_rsa.pub --kiosk
EOF
exit 0
}

# ── Parsing des arguments ────────────────────────────────────
[[ $# -eq 0 ]] && usage

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d) DEVICE="$2"; shift 2 ;;
    -i) IMAGE="$2"; shift 2 ;;
    -s) WIFI_SSID="$2"; shift 2 ;;
    -p) WIFI_PSK="$2"; shift 2 ;;
    -h) HOSTNAME="$2"; shift 2 ;;
    -u) USERNAME="$2"; shift 2 ;;
    -k) PUBKEY="$2"; shift 2 ;;
    -r) USB_OTP=true; shift ;;
    --kiosk) KIOSK=true; shift ;;
    --no-wifi) NO_WIFI=true; shift ;;
    --help) usage ;;
    *) error "Option inconnue : $1" ;;
  esac
done

# ── Vérifications préliminaires ─────────────────────────────
step "Vérifications préliminaires"

[[ $EUID -ne 0 ]] && error "Ce script doit être exécuté en root (sudo)"
[[ -z "$DEVICE" ]] && error "Périphérique cible non spécifié (-d)"
[[ -z "$IMAGE" ]] && error "Image non spécifiée (-i)"
[[ ! -e "$DEVICE" ]] && error "Périphérique introuvable : $DEVICE"
[[ ! -f "$IMAGE" ]] && error "Image introuvable : $IMAGE"

# Sécurité : refuser les disques système
for SYSDEV in /dev/sda /dev/nvme0n1 /dev/mmcblk0; do
  [[ "$DEVICE" == "$SYSDEV" ]] && \
    error "SÉCURITÉ : $DEVICE semble être un disque système. Abandon."
done

# Vérifier que le périphérique n'est pas monté
if grep -q "^$DEVICE" /proc/mounts 2>/dev/null; then
  warn "$DEVICE est monté. Démontage en cours..."
  umount "${DEVICE}"* 2>/dev/null || true
fi

# Vérifier les outils nécessaires
for tool in dd parted mount umount; do
  command -v "$tool" &>/dev/null || error "Outil manquant : $tool"
done

if [[ -n "$PUBKEY" && ! -f "$PUBKEY" ]]; then
  error "Clé SSH publique introuvable : $PUBKEY"
fi

ok "Vérifications passées"

# ── Confirmation ─────────────────────────────────────────────
step "Confirmation"
echo -e "  Périphérique cible : ${RED}${BOLD}$DEVICE${NC}"
echo -e "  Image source       : $IMAGE"
echo -e "  Nom d'hôte         : $HOSTNAME"
echo -e "  Utilisateur        : $USERNAME"
[[ -n "$WIFI_SSID" ]] && echo -e "  WiFi               : $WIFI_SSID"
[[ -n "$PUBKEY" ]] && echo -e "  Clé SSH            : $PUBKEY"
$KIOSK && echo -e "  Mode kiosk         : ${YELLOW}activé${NC}"
$USB_OTP && echo -e "  ${RED}USB OTP BOOT${NC}      : ${RED}IRRÉVERSIBLE${NC}"

echo ""
warn "TOUTES LES DONNÉES SUR $DEVICE SERONT EFFACÉES !"
read -r -p "Continuer ? [oui/NON] : " CONFIRM
[[ "$CONFIRM" != "oui" ]] && { info "Annulé."; exit 0; }

# ── Flash de l'image ─────────────────────────────────────────
step "Flash de l'image sur $DEVICE"

# Support des images compressées .xz
if [[ "$IMAGE" == *.xz ]]; then
  info "Image compressée détectée, décompression à la volée..."
  command -v xzcat &>/dev/null || error "xzcat requis pour les images .xz"
  xzcat "$IMAGE" | dd of="$DEVICE" bs=4M status=progress conv=fsync
else
  dd if="$IMAGE" of="$DEVICE" bs=4M status=progress conv=fsync
fi

sync
ok "Image flashée"

# ── Détection des partitions ──────────────────────────────────
step "Détection des partitions"
sleep 2
partprobe "$DEVICE" 2>/dev/null || true
sleep 1

# Détecter la partition boot (/boot/firmware sur bookworm = part1)
# et la partition root (part2)
if [[ "$DEVICE" == *mmcblk* || "$DEVICE" == *loop* ]]; then
  BOOT_PART="${DEVICE}p1"
  ROOT_PART="${DEVICE}p2"
else
  BOOT_PART="${DEVICE}1"
  ROOT_PART="${DEVICE}2"
fi

[[ ! -b "$BOOT_PART" ]] && error "Partition boot introuvable : $BOOT_PART"
[[ ! -b "$ROOT_PART" ]] && error "Partition root introuvable : $ROOT_PART"

ok "Partitions détectées : boot=$BOOT_PART root=$ROOT_PART"

# ── Montage ──────────────────────────────────────────────────
step "Montage des partitions"
mkdir -p "$BOOT_MNT" "$ROOT_MNT"

mount "$BOOT_PART" "$BOOT_MNT" || error "Impossible de monter $BOOT_PART"
mount "$ROOT_PART" "$ROOT_MNT" || error "Impossible de monter $ROOT_PART"

# Trap de nettoyage en cas d'erreur
cleanup() {
  info "Nettoyage..."
  umount "$BOOT_MNT" 2>/dev/null || true
  umount "$ROOT_MNT" 2>/dev/null || true
  rmdir "$BOOT_MNT" "$ROOT_MNT" 2>/dev/null || true
}
trap cleanup EXIT

ok "Partitions montées"

# ── Détection du chemin boot (bookworm vs bullseye) ──────────
# Bookworm : /boot/firmware/  |  Bullseye : /boot/
BOOT_FW="$BOOT_MNT"
if [[ -f "$ROOT_MNT/boot/firmware/config.txt" ]]; then
  # Chemin via root (plus fiable pour éditer config.txt via root)
  BOOT_FW_ROOT="$ROOT_MNT/boot/firmware"
else
  BOOT_FW_ROOT="$BOOT_MNT"
fi

# ── SSH ──────────────────────────────────────────────────────
step "Activation SSH"
touch "$BOOT_MNT/ssh"
ok "SSH activé (fichier ssh créé)"

# ── Clé SSH ──────────────────────────────────────────────────
if [[ -n "$PUBKEY" ]]; then
  step "Installation de la clé SSH publique"
  SSH_DIR="$ROOT_MNT/home/$USERNAME/.ssh"
  mkdir -p "$SSH_DIR"
  cat "$PUBKEY" >> "$SSH_DIR/authorized_keys"
  chmod 700 "$SSH_DIR"
  chmod 600 "$SSH_DIR/authorized_keys"
  # Propriétaire : UID 1000 (pi par défaut sur RPi OS)
  chown -R 1000:1000 "$SSH_DIR"
  ok "Clé SSH installée pour $USERNAME"
fi

# ── WiFi ─────────────────────────────────────────────────────
if ! $NO_WIFI && [[ -n "$WIFI_SSID" ]]; then
  step "Configuration WiFi"
  cat > "$BOOT_MNT/wpa_supplicant.conf" << WPAEOF
country=FR
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1

network={
    ssid="$WIFI_SSID"
    psk="$WIFI_PSK"
    key_mgmt=WPA-PSK
    proto=RSN
    pairwise=CCMP
    group=CCMP
}
WPAEOF
  ok "wpa_supplicant.conf créé pour $WIFI_SSID"
fi

# ── Nom d'hôte ───────────────────────────────────────────────
step "Configuration du nom d'hôte"
echo "$HOSTNAME" > "$ROOT_MNT/etc/hostname"
# Mettre à jour /etc/hosts
sed -i "s/raspberrypi/$HOSTNAME/g" "$ROOT_MNT/etc/hosts" 2>/dev/null || true
ok "Hostname : $HOSTNAME"

# ── HyperPixel 2.1 Round Touch ───────────────────────────────
step "Configuration HyperPixel 2.1 Round Touch"

CONFIG_TXT="$BOOT_MNT/config.txt"
[[ ! -f "$CONFIG_TXT" ]] && CONFIG_TXT="$BOOT_MNT/firmware/config.txt"
[[ ! -f "$CONFIG_TXT" ]] && error "config.txt introuvable"

# Supprimer tout overlay hyperpixel existant pour éviter les doublons
sed -i '/hyperpixel/d' "$CONFIG_TXT"

cat >> "$CONFIG_TXT" << CFGEOF

# ── HyperPixel 2.1 Round Touch ──────────────────────────────
# Overlay officiel Pimoroni (installé via firstrun ou git clone)
# Note: nécessite le driver Pimoroni installé au 1er boot
dtoverlay=hyperpixel2r
display_rotate=0

# I2C pour le touch FT3x7 (bus 10/11 sur SPI0)
dtparam=i2c_arm=on
dtparam=spi=on
CFGEOF

ok "config.txt mis à jour pour HyperPixel 2.1 Round"

# ── Script firstrun : install driver Pimoroni ─────────────────
step "Script firstrun : installation driver Pimoroni"

FIRSTRUN="$ROOT_MNT/etc/rc.local"

# Sauvegarder rc.local original
[[ -f "$FIRSTRUN" ]] && cp "$FIRSTRUN" "${FIRSTRUN}.bak"

cat > "$FIRSTRUN" << FIRSTEOF
#!/bin/bash
# rc.local - Exécuté au 1er boot
# Installe le driver HyperPixel 2.1 Round Touch

LOGFILE="/var/log/firstrun_hyperpixel.log"
DONE_FLAG="/etc/.hyperpixel_installed"

exec >> "\$LOGFILE" 2>&1
echo "=== firstrun \$(date) ==="

if [[ -f "\$DONE_FLAG" ]]; then
  echo "Driver déjà installé, skip."
  exit 0
fi

# Attendre le réseau (max 60s)
echo "Attente réseau..."
for i in \$(seq 1 12); do
  ping -c1 -W5 8.8.8.8 &>/dev/null && break
  sleep 5
done

if ! ping -c1 -W5 8.8.8.8 &>/dev/null; then
  echo "ERREUR: Pas de réseau après 60s. Install driver manuelle requise."
  exit 1
fi

echo "Réseau OK. Installation driver HyperPixel 2.1 Round..."
apt-get update -y
apt-get install -y git python3-pip

cd /tmp
rm -rf hyperpixel2r
git clone https://github.com/pimoroni/hyperpixel2r
cd hyperpixel2r

# Install non-interactive
echo "yes" | ./install.sh

touch "\$DONE_FLAG"
echo "=== Driver installé. Reboot dans 5s... ==="
sleep 5
reboot
FIRSTEOF

chmod +x "$FIRSTRUN"
ok "Script firstrun créé dans $FIRSTRUN"

# ── Mode kiosk (optionnel) ────────────────────────────────────
if $KIOSK; then
  step "Préparation mode kiosk Chromium"

  KIOSK_SERVICE="$ROOT_MNT/etc/systemd/system/kiosk.service"

  cat > "$KIOSK_SERVICE" << SVCEOF
[Unit]
Description=HyperPixel 2.1 Round - Kiosk Chromium
After=network.target graphical.target

[Service]
Type=simple
User=$USERNAME
Environment=DISPLAY=:0
Environment=XAUTHORITY=/home/$USERNAME/.Xauthority
ExecStartPre=/bin/sleep 5
ExecStart=/usr/bin/chromium-browser \\
  --kiosk \\
  --window-size=480,480 \\
  --start-fullscreen \\
  --no-first-run \\
  --disable-infobars \\
  --disable-session-crashed-bubble \\
  --disable-restore-session-state \\
  --app=http://localhost:8080
Restart=always
RestartSec=5

[Install]
WantedBy=graphical.target
SVCEOF

  # Activer le service au démarrage
  ln -sf /etc/systemd/system/kiosk.service \
    "$ROOT_MNT/etc/systemd/system/graphical.target.wants/kiosk.service" 2>/dev/null || true

  ok "Service kiosk.service créé (Chromium → http://localhost:8080)"
fi

# ── USB OTP boot (optionnel, IRRÉVERSIBLE) ────────────────────
if $USB_OTP; then
  step "Activation USB OTP boot"
  warn "ATTENTION : Opération IRRÉVERSIBLE sur le RPi Zero W !"
  warn "La fuse OTP sera gravée au prochain démarrage."

  CONFIG_TXT="$BOOT_MNT/config.txt"
  if ! grep -q "program_usb_boot_mode" "$CONFIG_TXT"; then
    cat >> "$CONFIG_TXT" << OTPEOF

# USB Boot OTP (IRRÉVERSIBLE)
program_usb_boot_mode=1
OTPEOF
    ok "USB boot OTP ajouté à config.txt"
  else
    info "program_usb_boot_mode déjà présent dans config.txt"
  fi
fi

# ── Résumé config.txt final ───────────────────────────────────
step "Contenu final de config.txt (section HyperPixel)"
grep -A 8 "HyperPixel" "$BOOT_MNT/config.txt" || true

# ── Démontage ─────────────────────────────────────────────────
step "Démontage et sync"
sync
umount "$BOOT_MNT"
umount "$ROOT_MNT"
rmdir "$BOOT_MNT" "$ROOT_MNT" 2>/dev/null || true
trap - EXIT

# ── Résumé final ─────────────────────────────────────────────
step "Terminé !"
echo ""
echo -e "  ${GREEN}✓${NC} Image flashée et configurée sur ${BOLD}$DEVICE${NC}"
echo -e "  ${GREEN}✓${NC} SSH activé"
[[ -n "$WIFI_SSID" ]] && echo -e "  ${GREEN}✓${NC} WiFi : $WIFI_SSID"
[[ -n "$PUBKEY" ]]    && echo -e "  ${GREEN}✓${NC} Clé SSH installée pour $USERNAME"
echo -e "  ${GREEN}✓${NC} HyperPixel 2.1 Round : overlay dtoverlay=hyperpixel2r"
echo -e "  ${GREEN}✓${NC} Driver Pimoroni : installation automatique au 1er boot"
$KIOSK   && echo -e "  ${GREEN}✓${NC} Mode kiosk Chromium configuré (port 8080)"
$USB_OTP && echo -e "  ${YELLOW}!${NC} USB OTP boot : sera gravé au 1er démarrage"
echo ""
echo -e "  ${BOLD}Étapes suivantes :${NC}"
echo -e "   1. Insérer la microSD dans le RPi Zero W"
echo -e "   2. Brancher l'alimentation (port PWR)"
echo -e "   3. Patienter ~3 min pour l'install driver + reboot"
echo -e "   4. SSH : ${CYAN}ssh $USERNAME@$HOSTNAME.local${NC}"
echo -e "   5. Vérifier touch : ${CYAN}i2cdetect -y 10${NC}"
echo ""
EOF
