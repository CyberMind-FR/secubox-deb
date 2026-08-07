#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: secubox-wait-network.sh — attente reseau avant les frontaux
#
# POURQUOI CE SCRIPT A ETE REECRIT (#998)
#
# La version precedente vivait dans /usr/local/bin, hors de tout paquet, et
# etait ecrite pour une AUTRE topologie : elle attendait l'adresse de gestion
# sur `lan0`.
#
# Sur cette board, `lan0`..`lan3` sont les ports du switch et n'ont PAS de
# porteuse ; l'adresse est portee par `eth2`. Le script attendait donc 80
# secondes une adresse qui n'arriverait jamais, puis, en repli, faisait :
#
#     ip addr add 192.168.1.200/24 dev lan0
#
# — il assignait l'adresse de gestion de la board a un port mort, a chaque
# demarrage. Et sa lenteur puis son echec faisaient abandonner le job de
# HAProxy, qui en dependait par `Requires=` : le 2026-08-06, la board est
# restee 53 minutes SANS HTTPS apres un redemarrage, sans que rien ne le
# signale.
#
# DEUX PRINCIPES TIENNENT DESORMAIS :
#
#   1. L'interface n'est plus codee en dur. On cherche celle qui PORTE
#      reellement l'adresse, ou a defaut celle que netplan declare. Une board
#      n'a pas toutes le meme cablage.
#
#   2. Ce script NE PEUT PAS FAIRE ECHOUER LE DEMARRAGE. Il sort toujours en
#      succes. Un assistant d'attente qui echoue ne doit jamais emporter avec
#      lui le frontal TLS de la machine — c'est precisement ce qui s'est
#      produit. Ce qu'il n'a pas pu faire, il le JOURNALISE.

set -uo pipefail

readonly TIMEOUT="${SECUBOX_NET_TIMEOUT:-45}"
readonly LOOPBACK_ALIAS="${SECUBOX_LOOPBACK_ALIAS:-192.168.255.1/24}"

log() { printf 'SecuBox: %s\n' "$*"; }

# ── Quelle interface porte le LAN ? ─────────────────────────────────────────
#
# Ordre de preference : celle qui a deja une adresse et une porteuse, puis la
# route par defaut, puis la premiere interface netplan avec porteuse. Aucune
# n'est codee en dur.
detect_lan_iface() {
    local ifc

    # 1. Interface portant la route par defaut — le signal le plus fiable.
    ifc=$(ip -4 route show default 2>/dev/null | awk '/default/{print $5; exit}')
    if [ -n "$ifc" ] && [ "$ifc" != "lo" ]; then
        printf '%s' "$ifc"; return 0
    fi

    # 2. Premiere interface non-loopback avec une adresse IPv4 ET une porteuse.
    while read -r _ ifc _; do
        ifc="${ifc%:}"
        [ "$ifc" = "lo" ] && continue
        case "$ifc" in br-*|lxc*|veth*|wg*|docker*) continue ;; esac
        ip -4 addr show "$ifc" 2>/dev/null | grep -q 'inet ' || continue
        [ "$(cat "/sys/class/net/$ifc/carrier" 2>/dev/null)" = "1" ] || continue
        printf '%s' "$ifc"; return 0
    done < <(ip -o link show 2>/dev/null)

    return 1
}

# ── Attente ─────────────────────────────────────────────────────────────────
log "attente d'une interface LAN operationnelle (max ${TIMEOUT}s)"
iface=""
for i in $(seq 1 "$TIMEOUT"); do
    if iface=$(detect_lan_iface); then
        log "LAN operationnel sur ${iface} apres ${i}s"
        break
    fi
    # A mi-parcours, une relance de netplan peut debloquer une configuration
    # qui n'a pas ete appliquee. Sans insister : si netplan echoue, le
    # demarrage continue quand meme.
    [ "$i" -eq $((TIMEOUT / 2)) ] && { log "relance de netplan"; netplan apply 2>/dev/null || true; }
    sleep 1
    iface=""
done

if [ -z "$iface" ]; then
    # PAS de repli qui assigne l'adresse de gestion a une interface au hasard :
    # l'ancienne version le faisait sur un port sans porteuse, ce qui ne
    # rétablissait rien et pouvait creer un doublon d'adresse sur le reseau.
    log "AUCUNE interface LAN operationnelle apres ${TIMEOUT}s"
    log "les frontaux demarrent quand meme — ils ecouteront des que le reseau viendra"
fi

# ── Alias de bouclage ───────────────────────────────────────────────────────
#
# nginx ecoute sur cette adresse (cf. /etc/nginx/sites-available/secubox).
# Elle etait posee par un fragment ifupdown `lo:0`, syntaxe abandonnee sur
# Debian moderne — c'est ce qui faisait echouer networking.service alors que
# la machine utilise netplan/networkd. On la pose ici, idempotemment.
ip link set lo up 2>/dev/null || true
if ! ip -4 addr show lo 2>/dev/null | grep -q "${LOOPBACK_ALIAS%%/*}"; then
    if ip addr add "$LOOPBACK_ALIAS" dev lo 2>/dev/null; then
        log "alias de bouclage ${LOOPBACK_ALIAS} pose"
    else
        log "alias de bouclage ${LOOPBACK_ALIAS} NON pose — nginx peut refuser de demarrer"
    fi
fi

# ── Ponts et veth des conteneurs ────────────────────────────────────────────
ip link set br-lxc up 2>/dev/null || true
for veth in $(ip -o link show type veth 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1); do
    ip link set "$veth" up 2>/dev/null || true
done

# TOUJOURS un succes : voir l'en-tete. Un assistant d'attente ne doit pas
# pouvoir emporter le frontal TLS.
exit 0
