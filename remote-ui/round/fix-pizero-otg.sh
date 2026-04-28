#!/bin/bash
# ==============================================================================
# SecuBox Eye Remote - Fix Pi Zero OTG Network & Serial
# Patch une SD card Pi Zero pour activer réseau USB et console série
#
# Usage:
#   1. Retirer la SD card du Pi Zero
#   2. L'insérer dans le PC
#   3. sudo bash fix-pizero-otg.sh /dev/sdX
#
# CyberMind - https://cybermind.fr
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[FIX]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
err() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# ==============================================================================
# Arguments
# ==============================================================================
if [[ $# -lt 1 ]]; then
    echo "Usage: sudo $0 /dev/sdX"
    echo ""
    echo "Exemple: sudo $0 /dev/sdc"
    echo ""
    echo "Partitions attendues:"
    echo "  /dev/sdX1 = boot (FAT32)"
    echo "  /dev/sdX2 = rootfs (ext4)"
    exit 1
fi

DEVICE="$1"

# Sécurité : refuser les disques système
if [[ "$DEVICE" == "/dev/sda" ]] || [[ "$DEVICE" == "/dev/nvme0n1" ]]; then
    err "Refus de modifier le disque système $DEVICE"
    exit 1
fi

# Check root
if [[ $EUID -ne 0 ]]; then
    err "Ce script doit être exécuté en root (sudo)"
    exit 1
fi

# Détecter les partitions
if [[ "$DEVICE" == *"mmcblk"* ]] || [[ "$DEVICE" == *"nvme"* ]]; then
    BOOT_PART="${DEVICE}p1"
    ROOT_PART="${DEVICE}p2"
else
    BOOT_PART="${DEVICE}1"
    ROOT_PART="${DEVICE}2"
fi

if [[ ! -b "$BOOT_PART" ]] || [[ ! -b "$ROOT_PART" ]]; then
    err "Partitions non trouvées: $BOOT_PART et $ROOT_PART"
    exit 1
fi

log "Device: $DEVICE"
log "Boot: $BOOT_PART"
log "Root: $ROOT_PART"

# ==============================================================================
# Montage
# ==============================================================================
BOOT_MNT="/tmp/pizero-boot-$$"
ROOT_MNT="/tmp/pizero-root-$$"

mkdir -p "$BOOT_MNT" "$ROOT_MNT"

cleanup() {
    log "Nettoyage..."
    umount "$BOOT_MNT" 2>/dev/null || true
    umount "$ROOT_MNT" 2>/dev/null || true
    rmdir "$BOOT_MNT" "$ROOT_MNT" 2>/dev/null || true
}
trap cleanup EXIT

log "Montage des partitions..."
mount "$BOOT_PART" "$BOOT_MNT"
mount "$ROOT_PART" "$ROOT_MNT"

# ==============================================================================
# 1. config.txt - Activer dwc2 overlay
# ==============================================================================
log "Configuration boot/config.txt..."

CONFIG_TXT="$BOOT_MNT/config.txt"
if [[ ! -f "$CONFIG_TXT" ]]; then
    # Pi OS Bookworm utilise /boot/firmware/
    CONFIG_TXT="$ROOT_MNT/boot/firmware/config.txt"
fi

if [[ -f "$CONFIG_TXT" ]]; then
    # Backup
    cp "$CONFIG_TXT" "${CONFIG_TXT}.bak"

    # Ajouter dtoverlay=dwc2 si absent
    if ! grep -q "dtoverlay=dwc2" "$CONFIG_TXT"; then
        echo "" >> "$CONFIG_TXT"
        echo "# USB OTG Gadget mode" >> "$CONFIG_TXT"
        echo "dtoverlay=dwc2" >> "$CONFIG_TXT"
        log "  Ajouté: dtoverlay=dwc2"
    else
        log "  dtoverlay=dwc2 déjà présent"
    fi
else
    warn "config.txt non trouvé"
fi

# ==============================================================================
# 2. cmdline.txt - Ajouter modules-load=dwc2,g_cdc (fallback simple)
# ==============================================================================
# Note: On utilise libcomposite plutôt que g_cdc, mais c'est un fallback
CMDLINE="$BOOT_MNT/cmdline.txt"
if [[ ! -f "$CMDLINE" ]]; then
    CMDLINE="$ROOT_MNT/boot/firmware/cmdline.txt"
fi

if [[ -f "$CMDLINE" ]]; then
    if ! grep -q "modules-load=dwc2" "$CMDLINE"; then
        # Ne pas ajouter g_cdc car on utilise libcomposite
        log "  cmdline.txt: modules-load sera géré par /etc/modules"
    fi
fi

# ==============================================================================
# 3. /etc/modules - Charger dwc2 et libcomposite
# ==============================================================================
log "Configuration /etc/modules..."

MODULES_FILE="$ROOT_MNT/etc/modules"
if [[ -f "$MODULES_FILE" ]]; then
    for mod in dwc2 libcomposite; do
        if ! grep -q "^$mod" "$MODULES_FILE"; then
            echo "$mod" >> "$MODULES_FILE"
            log "  Ajouté: $mod"
        fi
    done
fi

# ==============================================================================
# 4. /etc/network/interfaces.d/usb0 - IP statique
# ==============================================================================
log "Configuration réseau USB (usb0)..."

mkdir -p "$ROOT_MNT/etc/network/interfaces.d"

cat > "$ROOT_MNT/etc/network/interfaces.d/usb0" << 'EOF'
# SecuBox Eye Remote - USB OTG Network
# IP statique pour connexion avec SecuBox host

allow-hotplug usb0
iface usb0 inet static
    address 10.55.0.2
    netmask 255.255.255.252
    gateway 10.55.0.1
EOF

log "  Créé: /etc/network/interfaces.d/usb0 (10.55.0.2/30)"

# ==============================================================================
# 5. Getty sur ttyGS0 - Console série USB
# ==============================================================================
log "Activation console série (ttyGS0)..."

# Créer le lien systemd pour getty sur ttyGS0
GETTY_DIR="$ROOT_MNT/etc/systemd/system/getty.target.wants"
mkdir -p "$GETTY_DIR"

# Lien symbolique vers le service getty template
ln -sf /lib/systemd/system/getty@.service \
    "$GETTY_DIR/getty@ttyGS0.service" 2>/dev/null || true

log "  Activé: getty@ttyGS0.service"

# ==============================================================================
# 6. Script gadget composite (ECM + ACM + mass_storage)
# ==============================================================================
log "Installation script gadget composite..."

GADGET_SCRIPT="$ROOT_MNT/usr/local/sbin/secubox-otg-gadget.sh"
mkdir -p "$(dirname "$GADGET_SCRIPT")"

cat > "$GADGET_SCRIPT" << 'GADGET_EOF'
#!/bin/bash
# SecuBox Eye Remote - USB Composite Gadget
# ECM (réseau) + ACM (série) + mass_storage (image SecuBox)
set -euo pipefail

GADGET_NAME="secubox"
GADGET_BASE="/sys/kernel/config/usb_gadget"
GADGET_PATH="$GADGET_BASE/$GADGET_NAME"

# Image à exposer (configurable)
MASS_STORAGE_FILE="${SECUBOX_IMAGE_FILE:-/opt/secubox/images/secubox-live.img}"

# MAC dérivée du serial RPi (déterministe)
get_mac() {
    local serial
    serial=$(grep -Po 'Serial\s*:\s*\K[0-9a-f]+' /proc/cpuinfo 2>/dev/null || echo "0000000000000000")
    # Host MAC
    echo "02:$(echo "$serial" | tail -c 11 | sed 's/../&:/g' | cut -c1-14)"
}

# Device MAC (différente de host)
get_dev_mac() {
    local serial
    serial=$(grep -Po 'Serial\s*:\s*\K[0-9a-f]+' /proc/cpuinfo 2>/dev/null || echo "0000000000000000")
    echo "12:$(echo "$serial" | tail -c 11 | sed 's/../&:/g' | cut -c1-14)"
}

start_gadget() {
    # Charger les modules
    modprobe libcomposite 2>/dev/null || true

    # Vérifier configfs
    if [[ ! -d "$GADGET_BASE" ]]; then
        mount -t configfs none /sys/kernel/config 2>/dev/null || true
    fi

    # Supprimer ancien gadget si existe
    if [[ -d "$GADGET_PATH" ]]; then
        stop_gadget
    fi

    # Créer le gadget
    mkdir -p "$GADGET_PATH"
    cd "$GADGET_PATH"

    # IDs USB (Linux Foundation composite)
    echo 0x1d6b > idVendor   # Linux Foundation
    echo 0x0104 > idProduct  # Multifunction Composite Gadget
    echo 0x0100 > bcdDevice
    echo 0x0200 > bcdUSB

    # Device class: composite
    echo 0xEF > bDeviceClass
    echo 0x02 > bDeviceSubClass
    echo 0x01 > bDeviceProtocol

    # Strings
    mkdir -p strings/0x409
    echo "SecuBox"              > strings/0x409/manufacturer
    echo "Eye Remote Gadget"    > strings/0x409/product
    grep -Po 'Serial\s*:\s*\K[0-9a-f]+' /proc/cpuinfo > strings/0x409/serialnumber 2>/dev/null || \
        echo "0000000000000000" > strings/0x409/serialnumber

    # Configuration
    mkdir -p configs/c.1/strings/0x409
    echo "ECM+ACM+Mass Storage" > configs/c.1/strings/0x409/configuration
    echo 250                    > configs/c.1/MaxPower

    # =========================================================================
    # Fonction 1: ECM (Ethernet CDC)
    # =========================================================================
    mkdir -p functions/ecm.usb0
    echo "$(get_mac)"     > functions/ecm.usb0/host_addr
    echo "$(get_dev_mac)" > functions/ecm.usb0/dev_addr
    ln -s functions/ecm.usb0 configs/c.1/

    # =========================================================================
    # Fonction 2: ACM (Serial CDC)
    # =========================================================================
    mkdir -p functions/acm.GS0
    ln -s functions/acm.GS0 configs/c.1/

    # =========================================================================
    # Fonction 3: Mass Storage (optionnel)
    # =========================================================================
    if [[ -f "$MASS_STORAGE_FILE" ]]; then
        mkdir -p functions/mass_storage.0/lun.0
        echo 1 > functions/mass_storage.0/stall
        echo 0 > functions/mass_storage.0/lun.0/cdrom
        echo 0 > functions/mass_storage.0/lun.0/ro
        echo 0 > functions/mass_storage.0/lun.0/nofua
        echo "$MASS_STORAGE_FILE" > functions/mass_storage.0/lun.0/file
        ln -s functions/mass_storage.0 configs/c.1/
        echo "[GADGET] Mass storage: $MASS_STORAGE_FILE"
    else
        echo "[GADGET] Pas d'image mass_storage: $MASS_STORAGE_FILE"
    fi

    # =========================================================================
    # Activer le gadget
    # =========================================================================
    UDC=$(ls /sys/class/udc | head -1)
    if [[ -n "$UDC" ]]; then
        echo "$UDC" > UDC
        echo "[GADGET] Activé sur $UDC"
    else
        echo "[GADGET] ERREUR: Pas de contrôleur UDC disponible"
        return 1
    fi

    # Attendre que usb0 apparaisse
    sleep 1

    # Configurer l'interface réseau
    if ip link show usb0 &>/dev/null; then
        ip link set usb0 up
        echo "[GADGET] Interface usb0 UP"
    fi
}

stop_gadget() {
    if [[ ! -d "$GADGET_PATH" ]]; then
        return 0
    fi

    cd "$GADGET_PATH"

    # Désactiver UDC
    echo "" > UDC 2>/dev/null || true

    # Supprimer les liens
    rm -f configs/c.1/ecm.usb0 2>/dev/null || true
    rm -f configs/c.1/acm.GS0 2>/dev/null || true
    rm -f configs/c.1/mass_storage.0 2>/dev/null || true

    # Supprimer les fonctions
    rmdir functions/ecm.usb0 2>/dev/null || true
    rmdir functions/acm.GS0 2>/dev/null || true
    rmdir functions/mass_storage.0/lun.0 2>/dev/null || true
    rmdir functions/mass_storage.0 2>/dev/null || true

    # Supprimer la config
    rmdir configs/c.1/strings/0x409 2>/dev/null || true
    rmdir configs/c.1 2>/dev/null || true

    # Supprimer strings
    rmdir strings/0x409 2>/dev/null || true

    # Supprimer le gadget
    cd /
    rmdir "$GADGET_PATH" 2>/dev/null || true

    echo "[GADGET] Arrêté"
}

status_gadget() {
    if [[ ! -d "$GADGET_PATH" ]]; then
        echo "Gadget non configuré"
        return 1
    fi

    echo "=== Gadget Status ==="
    echo "UDC: $(cat "$GADGET_PATH/UDC" 2>/dev/null || echo 'non actif')"
    echo ""
    echo "Fonctions:"
    ls -1 "$GADGET_PATH/configs/c.1/" 2>/dev/null | grep -v strings || echo "  (aucune)"
    echo ""
    echo "Interface réseau:"
    ip addr show usb0 2>/dev/null || echo "  usb0 non disponible"
}

case "${1:-start}" in
    start)
        start_gadget
        ;;
    stop)
        stop_gadget
        ;;
    restart)
        stop_gadget
        sleep 1
        start_gadget
        ;;
    status)
        status_gadget
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
GADGET_EOF

chmod +x "$GADGET_SCRIPT"
log "  Créé: $GADGET_SCRIPT"

# ==============================================================================
# 7. Service systemd pour le gadget
# ==============================================================================
log "Installation service systemd..."

cat > "$ROOT_MNT/etc/systemd/system/secubox-otg-gadget.service" << 'SERVICE_EOF'
[Unit]
Description=SecuBox OTG Composite Gadget (ECM+ACM+Mass Storage)
After=local-fs.target
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/secubox-otg-gadget.sh start
ExecStop=/usr/local/sbin/secubox-otg-gadget.sh stop

[Install]
WantedBy=multi-user.target
SERVICE_EOF

# Activer le service
mkdir -p "$ROOT_MNT/etc/systemd/system/multi-user.target.wants"
ln -sf /etc/systemd/system/secubox-otg-gadget.service \
    "$ROOT_MNT/etc/systemd/system/multi-user.target.wants/secubox-otg-gadget.service"

log "  Créé et activé: secubox-otg-gadget.service"

# ==============================================================================
# 8. Créer répertoire pour l'image (si absent)
# ==============================================================================
mkdir -p "$ROOT_MNT/opt/secubox/images"
log "  Créé: /opt/secubox/images/"

# ==============================================================================
# Résumé
# ==============================================================================
echo ""
echo "============================================================"
echo -e "${GREEN}Patch terminé!${NC}"
echo "============================================================"
echo ""
echo "Modifications effectuées:"
echo "  - config.txt: dtoverlay=dwc2"
echo "  - /etc/modules: dwc2, libcomposite"
echo "  - /etc/network/interfaces.d/usb0: IP 10.55.0.2/30"
echo "  - getty@ttyGS0.service: console série activée"
echo "  - secubox-otg-gadget.sh: script gadget composite"
echo "  - secubox-otg-gadget.service: démarrage auto"
echo ""
echo "IMPORTANT:"
echo "  1. Si vous avez une image SecuBox à exposer, copiez-la dans:"
echo "     /opt/secubox/images/secubox-live.img"
echo ""
echo "  2. Réinsérez la SD card dans le Pi Zero et démarrez"
echo ""
echo "  3. Côté host SecuBox, configurez l'interface USB:"
echo "     sudo ip link set <interface> up"
echo "     sudo ip addr add 10.55.0.1/30 dev <interface>"
echo ""
echo "  4. Testez:"
echo "     ping 10.55.0.2"
echo "     ssh pi@10.55.0.2"
echo "     screen /dev/ttyACM0 115200"
echo ""
