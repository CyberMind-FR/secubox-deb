#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# SecuBox Remote UI — secubox-otg-gadget.sh
# Configuration USB Gadget composé via libcomposite (ECM + ACM)
#
# Crée un périphérique USB composite avec :
#   - CDC-ECM (réseau Ethernet over USB) → usb0 @ 10.55.0.2/30
#   - CDC-ACM (série virtuelle)          → /dev/ttyGS0 @ 115200
#
# CyberMind — https://cybermind.fr
# Author: Gérald Kerma <gandalf@gk2.net>
# License: Proprietary / ANSSI CSPN candidate
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

readonly VERSION="1.0.0"
readonly GADGET_NAME="secubox"
readonly CONFIGFS="/sys/kernel/config/usb_gadget"
readonly GADGET_PATH="${CONFIGFS}/${GADGET_NAME}"

# USB IDs (Linux Foundation — Multifunction Composite Gadget)
readonly ID_VENDOR="0x1d6b"
readonly ID_PRODUCT="0x0104"
readonly BCD_DEVICE="0x0200"
readonly BCD_USB="0x0200"

# Manufacturer info
readonly MANUFACTURER="CyberMind SecuBox"
readonly PRODUCT="SecuBox Remote UI Round"

# Network configuration
readonly OTG_NETWORK_DEV="10.55.0.2"
readonly OTG_NETWORK_HOST="10.55.0.1"
readonly OTG_NETMASK="255.255.255.252"

# Logging
log()  { echo "[otg-gadget] $*"; logger -t secubox-otg-gadget "$*"; }
err()  { echo "[otg-gadget] ERROR: $*" >&2; logger -t secubox-otg-gadget -p err "$*"; }

# ══════════════════════════════════════════════════════════════════════════════
# Génération déterministe des adresses MAC depuis le serial RPi
# ══════════════════════════════════════════════════════════════════════════════

get_serial() {
    # Serial du Raspberry Pi (16 caractères hex)
    grep -oP 'Serial\s*:\s*\K[0-9a-f]+' /proc/cpuinfo 2>/dev/null || echo "0000000000000000"
}

generate_mac() {
    local serial="$1"
    local offset="$2"

    # Utiliser les 6 derniers octets du serial + offset pour générer la MAC
    # Préfixe 02: = locally administered, unicast
    local base_hex="${serial: -12}"

    # Ajouter l'offset au dernier octet
    local last_byte=$((16#${base_hex: -2} + offset))
    last_byte=$((last_byte % 256))
    local last_hex=$(printf "%02x" $last_byte)

    # Format MAC : 02:sb:XX:XX:XX:XX (sb = SecuBox)
    printf "02:sb:%s:%s:%s:%s" \
        "${base_hex:0:2}" "${base_hex:2:2}" "${base_hex:4:2}" "$last_hex"
}

# ══════════════════════════════════════════════════════════════════════════════
# Vérifications préalables
# ══════════════════════════════════════════════════════════════════════════════

check_prerequisites() {
    # Vérifier qu'on est root
    if [[ $EUID -ne 0 ]]; then
        err "Ce script doit être exécuté en root"
        return 1
    fi

    # Vérifier que configfs est monté
    if [[ ! -d "$CONFIGFS" ]]; then
        log "Montage de configfs..."
        modprobe configfs 2>/dev/null || true
        mount -t configfs none /sys/kernel/config 2>/dev/null || true

        if [[ ! -d "$CONFIGFS" ]]; then
            err "configfs non disponible"
            return 1
        fi
    fi

    # Charger les modules nécessaires
    modprobe libcomposite 2>/dev/null || true
    modprobe usb_f_ecm 2>/dev/null || true
    modprobe usb_f_acm 2>/dev/null || true

    # Vérifier la présence d'un UDC (USB Device Controller)
    if [[ ! -d /sys/class/udc ]] || [[ -z "$(ls /sys/class/udc 2>/dev/null)" ]]; then
        err "Aucun UDC trouvé — ce script doit être exécuté sur un RPi Zero W"
        return 1
    fi

    return 0
}

# ══════════════════════════════════════════════════════════════════════════════
# Création du gadget USB composé
# ══════════════════════════════════════════════════════════════════════════════

gadget_start() {
    log "Démarrage du gadget USB SecuBox v${VERSION}..."

    # Vérifier si déjà configuré
    if [[ -d "$GADGET_PATH" ]]; then
        log "Gadget déjà configuré, redémarrage..."
        gadget_stop
    fi

    # Récupérer le serial et générer les MAC
    local serial
    serial=$(get_serial)
    local mac_host mac_dev
    mac_host=$(generate_mac "$serial" 0)
    mac_dev=$(generate_mac "$serial" 1)

    log "Serial RPi: ${serial}"
    log "MAC host (SecuBox): ${mac_host}"
    log "MAC dev (Zero W):   ${mac_dev}"

    # Créer le répertoire gadget
    mkdir -p "$GADGET_PATH"
    cd "$GADGET_PATH"

    # Configuration USB de base
    echo "$ID_VENDOR"  > idVendor
    echo "$ID_PRODUCT" > idProduct
    echo "$BCD_DEVICE" > bcdDevice
    echo "$BCD_USB"    > bcdUSB

    # Classe USB : Misc Device (pour composite)
    echo 0xEF > bDeviceClass
    echo 0x02 > bDeviceSubClass
    echo 0x01 > bDeviceProtocol

    # Strings (langue 0x409 = anglais US)
    mkdir -p strings/0x409
    echo "$MANUFACTURER" > strings/0x409/manufacturer
    echo "$PRODUCT"      > strings/0x409/product
    echo "$serial"       > strings/0x409/serialnumber

    # ──── Fonction 1 : CDC-ECM (Ethernet) ────────────────────────────────────
    mkdir -p functions/ecm.usb0
    echo "$mac_host" > functions/ecm.usb0/host_addr
    echo "$mac_dev"  > functions/ecm.usb0/dev_addr

    # ──── Fonction 2 : CDC-ACM (Série) ───────────────────────────────────────
    mkdir -p functions/acm.usb0

    # ──── Configuration composite ────────────────────────────────────────────
    mkdir -p configs/c.1/strings/0x409
    echo "SecuBox Remote UI (ECM + ACM)" > configs/c.1/strings/0x409/configuration
    echo 500 > configs/c.1/MaxPower  # 500 mA

    # Lier les fonctions à la configuration
    ln -sf functions/ecm.usb0 configs/c.1/
    ln -sf functions/acm.usb0 configs/c.1/

    # ──── Activer le gadget ──────────────────────────────────────────────────
    local udc
    udc=$(ls /sys/class/udc | head -1)
    if [[ -z "$udc" ]]; then
        err "Aucun UDC disponible"
        return 1
    fi

    log "Activation sur UDC: ${udc}"
    echo "$udc" > UDC

    # Attendre que l'interface usb0 apparaisse
    local retry=0
    while [[ ! -d /sys/class/net/usb0 ]] && [[ $retry -lt 10 ]]; do
        sleep 0.5
        ((retry++))
    done

    if [[ -d /sys/class/net/usb0 ]]; then
        log "Interface usb0 créée"

        # Configurer l'IP
        ip addr flush dev usb0 2>/dev/null || true
        ip addr add "${OTG_NETWORK_DEV}/30" dev usb0
        ip link set usb0 up

        log "usb0 configuré: ${OTG_NETWORK_DEV}/30"
    else
        err "Interface usb0 non créée après 5s"
        return 1
    fi

    # Vérifier ttyGS0
    if [[ -c /dev/ttyGS0 ]]; then
        log "Console série ttyGS0 disponible"
    else
        log "Console série ttyGS0 non disponible (sera créée au branchement)"
    fi

    log "Gadget USB SecuBox démarré avec succès"
    return 0
}

# ══════════════════════════════════════════════════════════════════════════════
# Arrêt du gadget USB
# ══════════════════════════════════════════════════════════════════════════════

gadget_stop() {
    log "Arrêt du gadget USB SecuBox..."

    if [[ ! -d "$GADGET_PATH" ]]; then
        log "Gadget non configuré"
        return 0
    fi

    cd "$GADGET_PATH"

    # Désactiver le gadget
    if [[ -f UDC ]] && [[ -n "$(cat UDC 2>/dev/null)" ]]; then
        echo "" > UDC
        sleep 0.5
    fi

    # Supprimer les liens symboliques de la configuration
    rm -f configs/c.1/ecm.usb0 2>/dev/null || true
    rm -f configs/c.1/acm.usb0 2>/dev/null || true

    # Supprimer les répertoires strings de la configuration
    rmdir configs/c.1/strings/0x409 2>/dev/null || true

    # Supprimer la configuration
    rmdir configs/c.1 2>/dev/null || true

    # Supprimer les fonctions
    rmdir functions/ecm.usb0 2>/dev/null || true
    rmdir functions/acm.usb0 2>/dev/null || true

    # Supprimer les strings du gadget
    rmdir strings/0x409 2>/dev/null || true

    # Supprimer le gadget
    cd /
    rmdir "$GADGET_PATH" 2>/dev/null || true

    log "Gadget USB SecuBox arrêté"
    return 0
}

# ══════════════════════════════════════════════════════════════════════════════
# Status du gadget
# ══════════════════════════════════════════════════════════════════════════════

gadget_status() {
    echo "═══════════════════════════════════════════════════════════════"
    echo "SecuBox OTG Gadget Status"
    echo "═══════════════════════════════════════════════════════════════"

    if [[ -d "$GADGET_PATH" ]]; then
        echo "Gadget:     CONFIGURÉ"

        if [[ -f "$GADGET_PATH/UDC" ]] && [[ -n "$(cat "$GADGET_PATH/UDC" 2>/dev/null)" ]]; then
            echo "UDC:        $(cat "$GADGET_PATH/UDC")"
            echo "Activé:     OUI"
        else
            echo "Activé:     NON"
        fi

        if [[ -f "$GADGET_PATH/strings/0x409/serialnumber" ]]; then
            echo "Serial:     $(cat "$GADGET_PATH/strings/0x409/serialnumber")"
        fi
    else
        echo "Gadget:     NON CONFIGURÉ"
    fi

    echo ""
    echo "── Interfaces réseau ──"
    if ip link show usb0 &>/dev/null; then
        echo "usb0:       PRÉSENT"
        ip addr show usb0 | grep -E "inet |state " | sed 's/^/            /'
    else
        echo "usb0:       ABSENT"
    fi

    echo ""
    echo "── Console série ──"
    if [[ -c /dev/ttyGS0 ]]; then
        echo "ttyGS0:     DISPONIBLE"
    else
        echo "ttyGS0:     NON DISPONIBLE"
    fi

    echo ""
    echo "── Connectivité ──"
    if ping -c 1 -W 1 "$OTG_NETWORK_HOST" &>/dev/null; then
        echo "SecuBox:    JOIGNABLE (${OTG_NETWORK_HOST})"
    else
        echo "SecuBox:    NON JOIGNABLE (${OTG_NETWORK_HOST})"
    fi

    echo "═══════════════════════════════════════════════════════════════"
}

# ══════════════════════════════════════════════════════════════════════════════
# Reload (stop + start)
# ══════════════════════════════════════════════════════════════════════════════

gadget_reload() {
    log "Rechargement du gadget USB SecuBox..."
    gadget_stop
    sleep 1
    gadget_start
}

# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

case "${1:-}" in
    start)
        check_prerequisites && gadget_start
        ;;
    stop)
        gadget_stop
        ;;
    restart|reload)
        check_prerequisites && gadget_reload
        ;;
    status)
        gadget_status
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|reload|status}"
        echo ""
        echo "SecuBox OTG Gadget — Configure le RPi Zero W en périphérique USB composite"
        echo "  - CDC-ECM : Ethernet over USB (usb0 @ 10.55.0.2/30)"
        echo "  - CDC-ACM : Console série (/dev/ttyGS0 @ 115200)"
        exit 1
        ;;
esac
