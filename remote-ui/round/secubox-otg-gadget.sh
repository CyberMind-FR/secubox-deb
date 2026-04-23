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

readonly VERSION="1.8.0"
readonly GADGET_NAME="secubox"
readonly CONFIGFS="/sys/kernel/config/usb_gadget"
readonly GADGET_PATH="${CONFIGFS}/${GADGET_NAME}"

# Mass storage backing files
readonly MASS_STORAGE_DEBUG="/var/lib/secubox-debug.img"
readonly MASS_STORAGE_DEBUG_SIZE="64"  # MB
readonly MASS_STORAGE_FLASH="/var/lib/secubox-flash.img"  # Bootable image for eMMC flashing
readonly FLASH_IMAGES_DIR="/var/lib/secubox-images"       # Directory for downloaded images

# HID devices
readonly HID_KEYBOARD_DEV="/dev/hidg0"
readonly HID_REPORT_DESC="/sys/kernel/config/usb_gadget/${GADGET_NAME}/functions/hid.usb0/report_desc"

# Command queue for TTY mode automation
readonly CMD_QUEUE="/run/secubox-cmd-queue"
readonly AUTH_STATE="/run/secubox-auth-state.json"

# USB IDs (Linux Foundation — Multifunction Composite Gadget)
readonly ID_VENDOR="0x1d6b"
readonly ID_PRODUCT="0x0104"
readonly BCD_DEVICE="0x0200"
readonly BCD_USB="0x0200"

# Alternative: RNDIS for Windows compatibility (Microsoft subclass)
readonly ID_VENDOR_RNDIS="0x0525"
readonly ID_PRODUCT_RNDIS="0xa4a2"

# Manufacturer info
readonly MANUFACTURER="CyberMind SecuBox"
readonly PRODUCT="SecuBox Remote UI Round"

# Network configuration
readonly OTG_NETWORK_DEV="10.55.0.2"
readonly OTG_NETWORK_HOST="10.55.0.1"
readonly OTG_NETMASK="255.255.255.252"

# Persistent mode setting (survives reboot)
readonly MODE_FILE="/etc/secubox/gadget-mode"
readonly AUTO_MODE_FILE="/run/secubox-gadget-automode"

# Logging
log()  { echo "[otg-gadget] $*"; logger -t secubox-otg-gadget "$*"; }
err()  { echo "[otg-gadget] ERROR: $*" >&2; logger -t secubox-otg-gadget -p err "$*"; }

# ══════════════════════════════════════════════════════════════════════════════
# Auto-mode detection — smart mode selection based on boot conditions
# ══════════════════════════════════════════════════════════════════════════════

detect_auto_mode() {
    # Check for persistent mode setting first
    if [[ -f "$MODE_FILE" ]]; then
        local saved_mode
        saved_mode=$(cat "$MODE_FILE" 2>/dev/null | tr -d '[:space:]')
        if [[ -n "$saved_mode" && "$saved_mode" =~ ^(normal|flash|debug|tty|auth)$ ]]; then
            echo "$saved_mode"
            return 0
        fi
    fi

    # Check for flash mode trigger (USB host requesting boot)
    if [[ -f "/run/secubox-request-flash" ]]; then
        rm -f "/run/secubox-request-flash"
        echo "flash"
        return 0
    fi

    # Check for TTY mode trigger (command queue present)
    if [[ -f "$CMD_QUEUE" ]] && [[ -s "$CMD_QUEUE" ]]; then
        echo "tty"
        return 0
    fi

    # Check for auth mode trigger
    if [[ -f "$AUTH_STATE" ]]; then
        echo "auth"
        return 0
    fi

    # Default to normal mode (network + serial)
    echo "start"
}

set_persistent_mode() {
    local mode="$1"
    mkdir -p "$(dirname "$MODE_FILE")"
    echo "$mode" > "$MODE_FILE"
    log "Persistent mode set: $mode"
}

clear_persistent_mode() {
    rm -f "$MODE_FILE"
    log "Persistent mode cleared"
}

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
    modprobe usb_f_rndis 2>/dev/null || true
    modprobe usb_f_acm 2>/dev/null || true
    modprobe usb_f_mass_storage 2>/dev/null || true

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

    # ──── Fonction 1 : RNDIS (Windows compatible Ethernet) ──────────────────
    mkdir -p functions/rndis.usb0
    echo "$mac_host" > functions/rndis.usb0/host_addr
    echo "$mac_dev"  > functions/rndis.usb0/dev_addr
    # RNDIS compatible IDs for Windows
    echo "RNDIS"      > functions/rndis.usb0/os_desc/interface.rndis/compatible_id
    echo "5162001"    > functions/rndis.usb0/os_desc/interface.rndis/sub_compatible_id 2>/dev/null || true

    # ──── Fonction 2 : CDC-ECM (Linux/Mac Ethernet) ────────────────────────────
    mkdir -p functions/ecm.usb0
    echo "$mac_host" > functions/ecm.usb0/host_addr
    echo "$mac_dev"  > functions/ecm.usb0/dev_addr

    # ──── Fonction 3 : CDC-ACM (Série) ───────────────────────────────────────
    mkdir -p functions/acm.usb0

    # ──── OS Descriptor (Windows compatibility) ─────────────────────────────
    echo 1       > os_desc/use
    echo 0xcd    > os_desc/b_vendor_code
    echo "MSFT100" > os_desc/qw_sign

    # ──── Configuration composite ────────────────────────────────────────────
    mkdir -p configs/c.1/strings/0x409
    echo "SecuBox Remote UI (RNDIS + ECM + ACM)" > configs/c.1/strings/0x409/configuration
    echo 500 > configs/c.1/MaxPower  # 500 mA

    # Lier les fonctions à la configuration (ordre important pour Windows)
    ln -sf functions/rndis.usb0 configs/c.1/
    ln -sf functions/ecm.usb0 configs/c.1/
    ln -sf functions/acm.usb0 configs/c.1/

    # Link RNDIS to OS descriptor
    ln -sf configs/c.1 os_desc/ 2>/dev/null || true

    # ──── Activer le gadget ──────────────────────────────────────────────────
    local udc
    udc=$(ls /sys/class/udc | head -1)
    if [[ -z "$udc" ]]; then
        err "Aucun UDC disponible"
        return 1
    fi

    log "Activation sur UDC: ${udc}"
    echo "$udc" > UDC

    # Attendre que l'interface usb1 (ECM) apparaisse
    # Note: Le gadget composite crée usb0 (RNDIS/Windows) et usb1 (ECM/Linux-Mac)
    # On configure usb1 car les hôtes Linux utilisent le driver cdc_ether (ECM)
    local retry=0
    while [[ ! -d /sys/class/net/usb1 ]] && [[ $retry -lt 10 ]]; do
        sleep 0.5
        ((retry++))
    done

    if [[ -d /sys/class/net/usb1 ]]; then
        log "Interface usb1 (ECM) créée"

        # Configurer l'IP sur usb1 uniquement (évite le routage asymétrique)
        ip addr flush dev usb1 2>/dev/null || true
        ip addr add "${OTG_NETWORK_DEV}/30" dev usb1
        ip link set usb1 up

        log "usb1 configuré: ${OTG_NETWORK_DEV}/30"
    else
        err "Interface usb1 non créée après 5s"
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
    rm -f configs/c.1/rndis.usb0 2>/dev/null || true
    rm -f configs/c.1/ecm.usb0 2>/dev/null || true
    rm -f configs/c.1/acm.usb0 2>/dev/null || true
    rm -f os_desc/c.1 2>/dev/null || true

    # Supprimer les répertoires strings de la configuration
    rmdir configs/c.1/strings/0x409 2>/dev/null || true

    # Supprimer la configuration
    rmdir configs/c.1 2>/dev/null || true

    # Supprimer les fonctions
    rmdir functions/rndis.usb0 2>/dev/null || true
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
# Flash Mode — Present bootable image as USB mass storage for EspressoBin
# ══════════════════════════════════════════════════════════════════════════════

gadget_flash() {
    local image_file="${1:-}"

    log "=== SecuBox Flash Mode ==="
    log "Presenting bootable USB storage for EspressoBin recovery/flashing"

    # Check for image file
    if [[ -z "$image_file" ]]; then
        # Look for default images
        if [[ -f "$MASS_STORAGE_FLASH" ]]; then
            image_file="$MASS_STORAGE_FLASH"
        elif [[ -d "$FLASH_IMAGES_DIR" ]]; then
            image_file=$(ls -t "$FLASH_IMAGES_DIR"/*.img 2>/dev/null | head -1)
        fi
    fi

    if [[ -z "$image_file" ]] || [[ ! -f "$image_file" ]]; then
        err "No bootable image found!"
        err "Place image at: $MASS_STORAGE_FLASH"
        err "Or specify: $0 flash /path/to/image.img"
        return 1
    fi

    log "Using image: $image_file ($(du -h "$image_file" | cut -f1))"

    # Stop existing gadget
    gadget_stop

    # Récupérer le serial et générer les MAC
    local serial
    serial=$(get_serial)

    # Créer le gadget mass storage only
    mkdir -p "$GADGET_PATH"
    cd "$GADGET_PATH"

    # USB IDs for mass storage
    echo "0x1d6b" > idVendor   # Linux Foundation
    echo "0x0104" > idProduct  # Multifunction Composite Gadget
    echo "0x0200" > bcdDevice
    echo "0x0200" > bcdUSB

    # Device class
    echo 0x00 > bDeviceClass     # Per-interface class
    echo 0x00 > bDeviceSubClass
    echo 0x00 > bDeviceProtocol

    # Strings
    mkdir -p strings/0x409
    echo "$MANUFACTURER"              > strings/0x409/manufacturer
    echo "SecuBox Flash Recovery"     > strings/0x409/product
    echo "$serial"                    > strings/0x409/serialnumber

    # ──── Mass Storage Function ─────────────────────────────────────────
    mkdir -p functions/mass_storage.usb0
    echo 1 > functions/mass_storage.usb0/stall
    echo 0 > functions/mass_storage.usb0/lun.0/cdrom
    echo 0 > functions/mass_storage.usb0/lun.0/ro        # Read-write for flashing
    echo 0 > functions/mass_storage.usb0/lun.0/nofua
    echo 1 > functions/mass_storage.usb0/lun.0/removable
    echo "$image_file" > functions/mass_storage.usb0/lun.0/file

    # ──── Also add serial console for U-Boot interaction ───────────────
    mkdir -p functions/acm.usb0

    # Configuration
    mkdir -p configs/c.1/strings/0x409
    echo "SecuBox Flash Mode (Mass Storage + Serial)" > configs/c.1/strings/0x409/configuration
    echo 500 > configs/c.1/MaxPower

    # Link functions
    ln -sf functions/mass_storage.usb0 configs/c.1/
    ln -sf functions/acm.usb0 configs/c.1/

    # Activate
    local udc
    udc=$(ls /sys/class/udc | head -1)
    if [[ -z "$udc" ]]; then
        err "No UDC available"
        return 1
    fi

    log "Activating on UDC: ${udc}"
    echo "$udc" > UDC

    log ""
    log "╔══════════════════════════════════════════════════════════════╗"
    log "║           SecuBox Flash Mode ACTIVE                         ║"
    log "╠══════════════════════════════════════════════════════════════╣"
    log "║  Image: $(basename "$image_file")"
    log "║  Size:  $(du -h "$image_file" | cut -f1)"
    log "║                                                              ║"
    log "║  Connect Pi Zero DATA port to EspressoBin USB              ║"
    log "║  Power on EspressoBin → Should boot from USB               ║"
    log "║                                                              ║"
    log "║  Serial console available at /dev/ttyGS0                   ║"
    log "║  Use: screen /dev/ttyGS0 115200                            ║"
    log "╚══════════════════════════════════════════════════════════════╝"

    return 0
}

# ══════════════════════════════════════════════════════════════════════════════
# Debug Mode — Network + Mass Storage for file exchange
# ══════════════════════════════════════════════════════════════════════════════

gadget_debug() {
    log "=== SecuBox Debug Mode ==="
    log "Network (ECM) + Mass Storage + Serial"

    # Create debug image if not exists
    if [[ ! -f "$MASS_STORAGE_DEBUG" ]]; then
        log "Creating debug storage image (${MASS_STORAGE_DEBUG_SIZE}MB)..."
        mkdir -p "$(dirname "$MASS_STORAGE_DEBUG")"
        dd if=/dev/zero of="$MASS_STORAGE_DEBUG" bs=1M count="$MASS_STORAGE_DEBUG_SIZE" status=progress
        mkfs.vfat -n "SECUBOX-DBG" "$MASS_STORAGE_DEBUG"
        log "Debug image created: $MASS_STORAGE_DEBUG"
    fi

    # Stop existing gadget
    gadget_stop

    local serial
    serial=$(get_serial)
    local mac_host mac_dev
    mac_host=$(generate_mac "$serial" 0)
    mac_dev=$(generate_mac "$serial" 1)

    # Create gadget
    mkdir -p "$GADGET_PATH"
    cd "$GADGET_PATH"

    echo "$ID_VENDOR"  > idVendor
    echo "$ID_PRODUCT" > idProduct
    echo "$BCD_DEVICE" > bcdDevice
    echo "$BCD_USB"    > bcdUSB

    echo 0xEF > bDeviceClass
    echo 0x02 > bDeviceSubClass
    echo 0x01 > bDeviceProtocol

    mkdir -p strings/0x409
    echo "$MANUFACTURER"            > strings/0x409/manufacturer
    echo "SecuBox Debug Mode"       > strings/0x409/product
    echo "$serial"                  > strings/0x409/serialnumber

    # ECM Network
    mkdir -p functions/ecm.usb0
    echo "$mac_host" > functions/ecm.usb0/host_addr
    echo "$mac_dev"  > functions/ecm.usb0/dev_addr

    # Mass Storage (debug exchange)
    mkdir -p functions/mass_storage.usb0
    echo 1 > functions/mass_storage.usb0/stall
    echo 0 > functions/mass_storage.usb0/lun.0/cdrom
    echo 0 > functions/mass_storage.usb0/lun.0/ro
    echo 1 > functions/mass_storage.usb0/lun.0/removable
    echo "$MASS_STORAGE_DEBUG" > functions/mass_storage.usb0/lun.0/file

    # Serial
    mkdir -p functions/acm.usb0

    # Configuration
    mkdir -p configs/c.1/strings/0x409
    echo "SecuBox Debug (ECM + Storage + Serial)" > configs/c.1/strings/0x409/configuration
    echo 500 > configs/c.1/MaxPower

    ln -sf functions/ecm.usb0 configs/c.1/
    ln -sf functions/mass_storage.usb0 configs/c.1/
    ln -sf functions/acm.usb0 configs/c.1/

    # Activate
    local udc
    udc=$(ls /sys/class/udc | head -1)
    echo "$udc" > UDC

    # Configure network
    sleep 2
    if [[ -d /sys/class/net/usb0 ]]; then
        ip addr flush dev usb0 2>/dev/null || true
        ip addr add "${OTG_NETWORK_DEV}/30" dev usb0
        ip link set usb0 up
    fi

    log ""
    log "Debug mode active:"
    log "  Network: usb0 @ ${OTG_NETWORK_DEV}/30"
    log "  Storage: SECUBOX-DBG (${MASS_STORAGE_DEBUG_SIZE}MB FAT32)"
    log "  Serial:  /dev/ttyGS0"

    return 0
}

# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

# Status file for Round UI to read
readonly STATUS_FILE="/run/secubox-gadget-status.json"

# ══════════════════════════════════════════════════════════════════════════════
# TTY Mode — Virtual keyboard for automated U-Boot/debug commands
# Round UI shows command queue and execution status
# ══════════════════════════════════════════════════════════════════════════════

# USB HID Keyboard Report Descriptor (boot protocol keyboard)
# 8 bytes: modifier, reserved, key1-key6
HID_KEYBOARD_REPORT_DESC() {
    echo -ne '\x05\x01'      # Usage Page (Generic Desktop)
    echo -ne '\x09\x06'      # Usage (Keyboard)
    echo -ne '\xa1\x01'      # Collection (Application)
    echo -ne '\x05\x07'      #   Usage Page (Key Codes)
    echo -ne '\x19\xe0'      #   Usage Minimum (224) - Left Control
    echo -ne '\x29\xe7'      #   Usage Maximum (231) - Right GUI
    echo -ne '\x15\x00'      #   Logical Minimum (0)
    echo -ne '\x25\x01'      #   Logical Maximum (1)
    echo -ne '\x75\x01'      #   Report Size (1)
    echo -ne '\x95\x08'      #   Report Count (8)
    echo -ne '\x81\x02'      #   Input (Data, Variable, Absolute) - Modifier byte
    echo -ne '\x95\x01'      #   Report Count (1)
    echo -ne '\x75\x08'      #   Report Size (8)
    echo -ne '\x81\x01'      #   Input (Constant) - Reserved byte
    echo -ne '\x95\x06'      #   Report Count (6)
    echo -ne '\x75\x08'      #   Report Size (8)
    echo -ne '\x15\x00'      #   Logical Minimum (0)
    echo -ne '\x25\x65'      #   Logical Maximum (101)
    echo -ne '\x05\x07'      #   Usage Page (Key Codes)
    echo -ne '\x19\x00'      #   Usage Minimum (0)
    echo -ne '\x29\x65'      #   Usage Maximum (101)
    echo -ne '\x81\x00'      #   Input (Data, Array) - Key array
    echo -ne '\xc0'          # End Collection
}

gadget_tty() {
    log "=== SecuBox TTY Mode ==="
    log "Virtual keyboard for automated commands + Round UI status"

    gadget_stop

    local serial
    serial=$(get_serial)

    mkdir -p "$GADGET_PATH"
    cd "$GADGET_PATH"

    # USB IDs
    echo "$ID_VENDOR"  > idVendor
    echo "$ID_PRODUCT" > idProduct
    echo "$BCD_DEVICE" > bcdDevice
    echo "$BCD_USB"    > bcdUSB

    echo 0x00 > bDeviceClass
    echo 0x00 > bDeviceSubClass
    echo 0x00 > bDeviceProtocol

    mkdir -p strings/0x409
    echo "$MANUFACTURER"           > strings/0x409/manufacturer
    echo "SecuBox TTY Remote"      > strings/0x409/product
    echo "$serial"                 > strings/0x409/serialnumber

    # ──── HID Keyboard Function ─────────────────────────────────────────
    mkdir -p functions/hid.usb0
    echo 1 > functions/hid.usb0/protocol      # Keyboard
    echo 1 > functions/hid.usb0/subclass      # Boot interface
    echo 8 > functions/hid.usb0/report_length # 8 bytes
    HID_KEYBOARD_REPORT_DESC > functions/hid.usb0/report_desc

    # ──── Serial for bidirectional communication ────────────────────────
    mkdir -p functions/acm.usb0

    # Configuration
    mkdir -p configs/c.1/strings/0x409
    echo "SecuBox TTY (Keyboard + Serial)" > configs/c.1/strings/0x409/configuration
    echo 100 > configs/c.1/MaxPower

    ln -sf functions/hid.usb0 configs/c.1/
    ln -sf functions/acm.usb0 configs/c.1/

    # Activate
    local udc
    udc=$(ls /sys/class/udc | head -1)
    echo "$udc" > UDC

    # Create command queue
    mkdir -p "$(dirname "$CMD_QUEUE")"
    echo '[]' > "$CMD_QUEUE"
    chmod 666 "$CMD_QUEUE"

    log ""
    log "╔══════════════════════════════════════════════════════════════╗"
    log "║           SecuBox TTY Mode ACTIVE                           ║"
    log "╠══════════════════════════════════════════════════════════════╣"
    log "║  Keyboard: /dev/hidg0 (virtual USB keyboard)               ║"
    log "║  Serial:   /dev/ttyGS0 (bidirectional)                     ║"
    log "║  Queue:    $CMD_QUEUE                            ║"
    log "║                                                              ║"
    log "║  Round UI can send commands via queue file                 ║"
    log "║  Commands are typed as keyboard input to host              ║"
    log "╚══════════════════════════════════════════════════════════════╝"

    return 0
}

# ══════════════════════════════════════════════════════════════════════════════
# Auth Mode — Security token with QR code display (Eye Remote)
# Round UI shows QR codes for authentication, acts like YubiKey
# ══════════════════════════════════════════════════════════════════════════════

gadget_auth() {
    log "=== SecuBox Auth Mode (Eye Remote) ==="
    log "Security token + QR authentication display"

    gadget_stop

    local serial
    serial=$(get_serial)

    mkdir -p "$GADGET_PATH"
    cd "$GADGET_PATH"

    # USB IDs for security device
    echo "0x1050" > idVendor   # Yubico VID (for compatibility)
    echo "0x0407" > idProduct  # YubiKey-like
    echo "$BCD_DEVICE" > bcdDevice
    echo "0x0210" > bcdUSB     # USB 2.1 for BOS descriptor

    echo 0x00 > bDeviceClass
    echo 0x00 > bDeviceSubClass
    echo 0x00 > bDeviceProtocol

    mkdir -p strings/0x409
    echo "$MANUFACTURER"           > strings/0x409/manufacturer
    echo "SecuBox Eye Remote"      > strings/0x409/product
    echo "$serial"                 > strings/0x409/serialnumber

    # ──── HID for FIDO/U2F-like authentication ──────────────────────────
    mkdir -p functions/hid.usb0
    echo 0 > functions/hid.usb0/protocol
    echo 0 > functions/hid.usb0/subclass
    echo 64 > functions/hid.usb0/report_length
    # FIDO U2F HID report descriptor
    echo -ne '\x06\xd0\xf1'   > functions/hid.usb0/report_desc  # Usage Page (FIDO)
    echo -ne '\x09\x01'      >> functions/hid.usb0/report_desc  # Usage (U2F HID)
    echo -ne '\xa1\x01'      >> functions/hid.usb0/report_desc  # Collection (Application)
    echo -ne '\x09\x20'      >> functions/hid.usb0/report_desc  # Usage (Input Report Data)
    echo -ne '\x15\x00'      >> functions/hid.usb0/report_desc  # Logical Minimum (0)
    echo -ne '\x26\xff\x00'  >> functions/hid.usb0/report_desc  # Logical Maximum (255)
    echo -ne '\x75\x08'      >> functions/hid.usb0/report_desc  # Report Size (8)
    echo -ne '\x95\x40'      >> functions/hid.usb0/report_desc  # Report Count (64)
    echo -ne '\x81\x02'      >> functions/hid.usb0/report_desc  # Input (Data, Variable, Absolute)
    echo -ne '\x09\x21'      >> functions/hid.usb0/report_desc  # Usage (Output Report Data)
    echo -ne '\x15\x00'      >> functions/hid.usb0/report_desc  # Logical Minimum (0)
    echo -ne '\x26\xff\x00'  >> functions/hid.usb0/report_desc  # Logical Maximum (255)
    echo -ne '\x75\x08'      >> functions/hid.usb0/report_desc  # Report Size (8)
    echo -ne '\x95\x40'      >> functions/hid.usb0/report_desc  # Report Count (64)
    echo -ne '\x91\x02'      >> functions/hid.usb0/report_desc  # Output (Data, Variable, Absolute)
    echo -ne '\xc0'          >> functions/hid.usb0/report_desc  # End Collection

    # ──── Serial for secure channel ─────────────────────────────────────
    mkdir -p functions/acm.usb0

    # Configuration
    mkdir -p configs/c.1/strings/0x409
    echo "SecuBox Eye Remote (Auth + QR)" > configs/c.1/strings/0x409/configuration
    echo 100 > configs/c.1/MaxPower

    ln -sf functions/hid.usb0 configs/c.1/
    ln -sf functions/acm.usb0 configs/c.1/

    # Activate
    local udc
    udc=$(ls /sys/class/udc | head -1)
    echo "$udc" > UDC

    # Initialize auth state
    cat > "$AUTH_STATE" <<EOF
{
  "mode": "idle",
  "challenge": null,
  "qr_data": null,
  "last_auth": null,
  "pending_approval": false
}
EOF
    chmod 644 "$AUTH_STATE"

    log ""
    log "╔══════════════════════════════════════════════════════════════╗"
    log "║           SecuBox Eye Remote ACTIVE                         ║"
    log "╠══════════════════════════════════════════════════════════════╣"
    log "║  HID:    /dev/hidg0 (FIDO/U2F compatible)                  ║"
    log "║  Serial: /dev/ttyGS0 (secure channel)                      ║"
    log "║  State:  $AUTH_STATE                     ║"
    log "║                                                              ║"
    log "║  Round UI displays:                                        ║"
    log "║    - QR codes for mobile authentication                    ║"
    log "║    - Approval prompts (tap to confirm)                     ║"
    log "║    - Connection status (eye icon)                          ║"
    log "╚══════════════════════════════════════════════════════════════╝"

    return 0
}

write_status() {
    local mode="$1"
    local state="$2"
    local message="${3:-}"
    local extra="${4:-}"

    cat > "$STATUS_FILE" <<EOF
{
  "mode": "$mode",
  "state": "$state",
  "message": "$message",
  "timestamp": "$(date -Iseconds)",
  "extra": $extra
}
EOF
    chmod 644 "$STATUS_FILE"
}

case "${1:-}" in
    start)
        write_status "normal" "starting" "Initializing USB gadget..."
        if check_prerequisites && gadget_start; then
            write_status "normal" "active" "Network + Serial active" '{"ip": "10.55.0.2", "serial": "/dev/ttyGS0"}'
        else
            write_status "normal" "error" "Gadget startup failed"
        fi
        ;;
    stop)
        write_status "normal" "stopping" "Shutting down USB gadget..."
        gadget_stop
        write_status "idle" "stopped" "USB gadget inactive"
        ;;
    restart|reload)
        write_status "normal" "restarting" "Reloading USB gadget..."
        check_prerequisites && gadget_reload
        write_status "normal" "active" "Network + Serial active" '{"ip": "10.55.0.2", "serial": "/dev/ttyGS0"}'
        ;;
    status)
        gadget_status
        ;;
    flash)
        write_status "flash" "starting" "Entering Flash Mode..."
        if check_prerequisites && gadget_flash "${2:-}"; then
            local img_name
            img_name=$(basename "${2:-$MASS_STORAGE_FLASH}" 2>/dev/null || echo "unknown")
            write_status "flash" "active" "Boot USB active - waiting for EspressoBin" "{\"image\": \"$img_name\", \"serial\": \"/dev/ttyGS0\"}"
        else
            write_status "flash" "error" "Flash mode startup failed"
        fi
        ;;
    debug)
        write_status "debug" "starting" "Entering Debug Mode..."
        if check_prerequisites && gadget_debug; then
            write_status "debug" "active" "Network + Storage + Serial" '{"ip": "10.55.0.2", "storage": "SECUBOX-DBG", "serial": "/dev/ttyGS0"}'
        else
            write_status "debug" "error" "Debug mode startup failed"
        fi
        ;;
    tty)
        write_status "tty" "starting" "Entering TTY Mode..."
        if check_prerequisites && gadget_tty; then
            write_status "tty" "active" "Virtual keyboard ready" '{"keyboard": "/dev/hidg0", "serial": "/dev/ttyGS0", "queue": "/run/secubox-cmd-queue"}'
        else
            write_status "tty" "error" "TTY mode startup failed"
        fi
        ;;
    auth|eye)
        write_status "auth" "starting" "Entering Eye Remote Mode..."
        if check_prerequisites && gadget_auth; then
            write_status "auth" "active" "Eye Remote ready - waiting for challenge" '{"hid": "/dev/hidg0", "serial": "/dev/ttyGS0", "state": "/run/secubox-auth-state.json"}'
        else
            write_status "auth" "error" "Auth mode startup failed"
        fi
        ;;
    auto)
        # Smart auto-detection of optimal mode
        auto_mode=$(detect_auto_mode)
        log "Auto-detected mode: $auto_mode"
        write_status "$auto_mode" "auto-starting" "Auto-detected mode: $auto_mode"
        exec "$0" "$auto_mode"
        ;;
    set-mode)
        # Set persistent mode for next boot
        if [[ -n "${2:-}" ]]; then
            set_persistent_mode "$2"
        else
            echo "Usage: $0 set-mode {normal|flash|debug|tty|auth}"
        fi
        ;;
    clear-mode)
        clear_persistent_mode
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|auto|flash|debug|tty|auth}"
        echo ""
        echo "SecuBox OTG Gadget v${VERSION} — RPi Zero W USB composite device"
        echo ""
        echo "┌─────────────────────────────────────────────────────────────────┐"
        echo "│                     AVAILABLE MODES                             │"
        echo "├─────────────────────────────────────────────────────────────────┤"
        echo "│ start   │ Normal    │ Network (ECM) + Serial                   │"
        echo "│ flash   │ Recovery  │ Bootable USB + Serial (U-Boot access)    │"
        echo "│ debug   │ Debug     │ Network + Storage + Serial               │"
        echo "│ tty     │ Keyboard  │ Virtual keyboard + Serial (automation)   │"
        echo "│ auth    │ Eye Remote│ FIDO/U2F HID + QR display (security key) │"
        echo "├─────────────────────────────────────────────────────────────────┤"
        echo "│ stop    │           │ Disable USB gadget                       │"
        echo "│ restart │           │ Reload gadget configuration              │"
        echo "│ status  │           │ Show current gadget status               │"
        echo "│ auto    │           │ Smart auto-detect optimal mode           │"
        echo "│ set-mode│           │ Set persistent mode (survives reboot)    │"
        echo "└─────────────────────────────────────────────────────────────────┘"
        echo ""
        echo "Round UI Integration:"
        echo "  Status file: /run/secubox-gadget-status.json"
        echo "  TTY queue:   /run/secubox-cmd-queue"
        echo "  Auth state:  /run/secubox-auth-state.json"
        echo ""
        echo "Examples:"
        echo "  $0 start                    # Normal network mode"
        echo "  $0 tty                      # Virtual keyboard for U-Boot"
        echo "  $0 auth                     # Eye Remote security mode"
        echo "  $0 flash /path/to/image.img # Boot host from image"
        exit 1
        ;;
esac
