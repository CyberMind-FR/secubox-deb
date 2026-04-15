#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# SecuBox Remote UI — secubox-otg-host-up.sh
# Script udev côté hôte SecuBox pour configurer l'interface OTG
#
# Appelé par udev quand le Zero W est connecté en USB
# Configure l'interface secubox-round avec l'IP 10.55.0.1/30
#
# CyberMind — https://cybermind.fr
# Author: Gérald Kerma <gandalf@gk2.net>
# License: Proprietary / ANSSI CSPN candidate
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

readonly VERSION="1.0.0"
readonly OTG_HOST_IP="10.55.0.1"
readonly OTG_PEER_IP="10.55.0.2"
readonly OTG_NETMASK="30"
readonly INTERFACE="${INTERFACE:-secubox-round}"
readonly API_BASE="http://localhost:8000"
readonly LOG_TAG="secubox-otg-host"

# Logging
log()  { logger -t "$LOG_TAG" "$*"; echo "[otg-host] $*"; }
err()  { logger -t "$LOG_TAG" -p err "$*"; echo "[otg-host] ERROR: $*" >&2; }

# ══════════════════════════════════════════════════════════════════════════════
# Récupérer le token interne SecuBox (pour notification API)
# ══════════════════════════════════════════════════════════════════════════════

get_internal_token() {
    # Token interne stocké dans /etc/secubox/secrets/internal.token
    local token_file="/etc/secubox/secrets/internal.token"
    if [[ -f "$token_file" ]]; then
        cat "$token_file"
    else
        echo ""
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# Configuration de l'interface réseau
# ══════════════════════════════════════════════════════════════════════════════

configure_interface() {
    log "Configuration de l'interface ${INTERFACE}..."

    # Attendre que l'interface soit disponible
    local retry=0
    while ! ip link show "$INTERFACE" &>/dev/null && [[ $retry -lt 10 ]]; do
        sleep 0.5
        ((retry++))
    done

    if ! ip link show "$INTERFACE" &>/dev/null; then
        err "Interface ${INTERFACE} non trouvée après 5s"
        return 1
    fi

    # Flush des anciennes configurations
    ip addr flush dev "$INTERFACE" 2>/dev/null || true

    # Configuration IP
    ip addr add "${OTG_HOST_IP}/${OTG_NETMASK}" dev "$INTERFACE"
    ip link set "$INTERFACE" up

    log "Interface ${INTERFACE} configurée: ${OTG_HOST_IP}/${OTG_NETMASK}"

    # Attendre que le peer soit joignable
    log "Attente du peer ${OTG_PEER_IP}..."
    retry=0
    while ! ping -c 1 -W 1 "$OTG_PEER_IP" &>/dev/null && [[ $retry -lt 20 ]]; do
        sleep 1
        ((retry++))
    done

    if ping -c 1 -W 1 "$OTG_PEER_IP" &>/dev/null; then
        log "Peer ${OTG_PEER_IP} joignable"
        return 0
    else
        log "Peer ${OTG_PEER_IP} non joignable (sera retesté plus tard)"
        return 0  # Pas une erreur fatale
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# Notification à l'API SecuBox
# ══════════════════════════════════════════════════════════════════════════════

notify_api() {
    local action="$1"
    local token
    token=$(get_internal_token)

    if [[ -z "$token" ]]; then
        log "Pas de token interne, notification API ignorée"
        return 0
    fi

    local endpoint="${API_BASE}/api/v1/remote-ui/${action}"
    local data

    case "$action" in
        connected)
            data='{"transport":"otg","peer":"'"${OTG_PEER_IP}"'","interface":"'"${INTERFACE}"'"}'
            ;;
        disconnected)
            data='{"transport":"otg","peer":"'"${OTG_PEER_IP}"'"}'
            ;;
        *)
            log "Action inconnue: ${action}"
            return 1
            ;;
    esac

    log "Notification API: ${action}"

    # Appel API avec timeout court (ne pas bloquer udev)
    curl -s -m 5 -X POST "$endpoint" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/json" \
        -d "$data" &>/dev/null || true
}

# ══════════════════════════════════════════════════════════════════════════════
# Création du lien symbolique pour la console série
# ══════════════════════════════════════════════════════════════════════════════

setup_serial_link() {
    local tty_device="${1:-}"

    if [[ -z "$tty_device" ]]; then
        # Chercher le ttyACM correspondant au gadget SecuBox
        for tty in /dev/ttyACM*; do
            if [[ -c "$tty" ]]; then
                tty_device="$tty"
                break
            fi
        done
    fi

    if [[ -c "$tty_device" ]]; then
        # Créer le lien symbolique
        ln -sf "$tty_device" /dev/secubox-console
        log "Console série disponible: /dev/secubox-console → ${tty_device}"

        # Configurer les permissions
        chmod 660 "$tty_device"
        chown root:dialout "$tty_device" 2>/dev/null || true
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# Nettoyage à la déconnexion
# ══════════════════════════════════════════════════════════════════════════════

cleanup() {
    log "Nettoyage de la connexion OTG..."

    # Supprimer le lien symbolique de la console
    rm -f /dev/secubox-console 2>/dev/null || true

    # Notifier l'API
    notify_api "disconnected"

    log "Nettoyage terminé"
}

# ══════════════════════════════════════════════════════════════════════════════
# Écriture du fichier d'état
# ══════════════════════════════════════════════════════════════════════════════

write_state() {
    local state="$1"
    local state_file="/run/secubox/remote-ui-otg.state"

    mkdir -p "$(dirname "$state_file")"

    cat > "$state_file" << EOF
{
    "state": "${state}",
    "interface": "${INTERFACE}",
    "host_ip": "${OTG_HOST_IP}",
    "peer_ip": "${OTG_PEER_IP}",
    "timestamp": $(date +%s)
}
EOF

    log "État écrit: ${state}"
}

# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

case "${1:-up}" in
    up|add|start)
        log "Connexion OTG détectée (${INTERFACE})"
        configure_interface
        setup_serial_link "${2:-}"
        write_state "connected"
        notify_api "connected"
        log "Configuration OTG terminée"
        ;;

    down|remove|stop)
        log "Déconnexion OTG détectée (${INTERFACE})"
        write_state "disconnected"
        cleanup
        ;;

    status)
        if ip link show "$INTERFACE" &>/dev/null; then
            echo "Interface ${INTERFACE}: ACTIVE"
            ip addr show "$INTERFACE"
            if ping -c 1 -W 1 "$OTG_PEER_IP" &>/dev/null; then
                echo "Peer ${OTG_PEER_IP}: JOIGNABLE"
            else
                echo "Peer ${OTG_PEER_IP}: NON JOIGNABLE"
            fi
        else
            echo "Interface ${INTERFACE}: INACTIVE"
        fi

        if [[ -L /dev/secubox-console ]]; then
            echo "Console série: $(readlink /dev/secubox-console)"
        else
            echo "Console série: NON DISPONIBLE"
        fi
        ;;

    *)
        echo "Usage: $0 {up|down|status}"
        echo ""
        echo "SecuBox OTG Host — Configure l'interface OTG côté SecuBox"
        exit 1
        ;;
esac
