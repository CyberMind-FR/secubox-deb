#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: secubox-jitsi :: install-lxc.sh
#
# Idempotent LXC bootstrap for Jitsi Meet. Safe to re-run.
# Mirrors packages/secubox-jellyfin/lib/jellyfin/install-lxc.sh:
#   1. lxc-create -t download (unprivileged, idmap 0->100000)
#   2. ensure_masquerade() 10.100.0.0/24
#   3. ensure_resolv() via lxc-attach
#   4. official Jitsi apt repo + `apt-get install jitsi-meet` INSIDE the LXC
#
# Replaces the 1.0.0 module, which generated a docker-compose.yml and drove
# docker/podman from the FastAPI process. Two things were wrong with that: the
# project settled on native-in-LXC modules with their own systemd units
# (jellyfin, torrent, ytsas), and a webui driving a container runtime in-process
# bypasses the confined-ctl rule every other module follows.
#
# WHAT MAKES JITSI DIFFERENT from the other LXC modules here, and why this
# script does more than the jellyfin one:
#
#   - jitsi-meet is four cooperating services (prosody XMPP, jicofo, the
#     videobridge, and an nginx serving the web app), not one daemon. They are
#     wired together at install time by debconf answers — which is why this
#     script preseeds rather than post-edits.
#   - The videobridge carries media over UDP/10000 and must advertise an
#     address peers can actually reach. Behind TWO NATs (the LXC bridge, then
#     the ISP router) it cannot discover that alone: both the local and the
#     public address are declared explicitly. Getting this wrong is the classic
#     "call connects, then everyone is silent" failure.
#   - The web tier is entirely WebSocket. Anything that terminates or inspects
#     without forwarding the upgrade breaks it — hence the deliberate
#     waf_bypass on this vhost (see conf/jitsi.toml.example).

set -euo pipefail

readonly LXC_NAME="${SECUBOX_LXC_NAME:-jitsi}"
readonly LXC_IP="${SECUBOX_LXC_IP:-10.100.0.190}"
readonly LXC_PATH="${SECUBOX_LXC_PATH:-/data/lxc}"
readonly LXC_BRIDGE="${SECUBOX_LXC_BRIDGE:-br-lxc}"
readonly LXC_GW="${SECUBOX_LXC_GW:-10.100.0.1}"
readonly DEBIAN_SUITE="${SECUBOX_DEBIAN_SUITE:-bookworm}"
readonly JITSI_DOMAIN="${SECUBOX_JITSI_DOMAIN:-meet.gk2.secubox.in}"
readonly JVB_PORT="${SECUBOX_JITSI_JVB_PORT:-10000}"
readonly WEB_PORT="${SECUBOX_JITSI_WEB_PORT:-80}"
readonly STATE_DIR="${SECUBOX_STATE_DIR:-/etc/secubox/jitsi}"
readonly SECRETS_DIR="${SECUBOX_SECRETS_DIR:-/etc/secubox/secrets}"
readonly SENTINEL="$STATE_DIR/.lxc-provisioned"

log()  { printf '[jitsi-install] %s\n' "$*"; }
fail() { printf '[jitsi-install] ERROR: %s\n' "$*" >&2; exit 1; }

require_cmds() {
    for c in lxc-create lxc-info lxc-start lxc-attach nft; do
        command -v "$c" >/dev/null 2>&1 || fail "$c not installed"
    done
}

ensure_dirs() {
    install -d -m 0755 -o root -g root "$LXC_PATH"
    install -d -m 0755 -o root -g root "$STATE_DIR"
    install -d -m 0700 -o root -g root "$SECRETS_DIR"
}

ensure_bridge() {
    if ! ip link show "$LXC_BRIDGE" >/dev/null 2>&1; then
        log "Creating bridge $LXC_BRIDGE @ ${LXC_GW}/24 ..."
        ip link add name "$LXC_BRIDGE" type bridge
        ip addr add "${LXC_GW}/24" dev "$LXC_BRIDGE"
        ip link set "$LXC_BRIDGE" up
    fi
}

ensure_masquerade() {
    if ! nft list table ip lxc 2>/dev/null | grep -q 'saddr 10.100.0.0/24'; then
        log "Adding nftables MASQUERADE for 10.100.0.0/24 ..."
        nft 'add table ip lxc' 2>/dev/null || true
        nft 'add chain ip lxc postrouting { type nat hook postrouting priority srcnat ; policy accept ; }' 2>/dev/null || true
        nft 'add rule ip lxc postrouting ip saddr 10.100.0.0/24 ip daddr != 10.100.0.0/24 counter masquerade' 2>/dev/null || true
    fi
}

lxc_state() {
    lxc-info -n "$LXC_NAME" -P "$LXC_PATH" 2>/dev/null \
        | awk -F: '/^State:/ { gsub(/ /,"",$2); print tolower($2) }' || true
}

# Une création interrompue (SIGTERM en plein lxc-create, coupure réseau,
# manque de place) laisse un répertoire de conteneur AVEC un verrou de
# création. `lxc-start` y répond « Ongoing container creation detected » et
# toute relance échoue de la même façon, indéfiniment — l'idempotence naïve
# « le répertoire existe donc c'est bon » transforme alors un échec ponctuel en
# panne permanente qu'il faut dénouer à la main.
#
# lxc pose lui-même un fichier `partial` dans le répertoire du conteneur
# pendant la création et le retire à la fin : c'est exactement le marqueur sur
# lequel `lxc-start` refuse ensuite de démarrer. On teste donc CE marqueur, et
# non une heuristique — plus le garde de repli « config sans rootfs » pour le
# cas où le répertoire aurait été mutilé autrement.
clean_partial_lxc() {
    local dir="$LXC_PATH/$LXC_NAME"
    [ -d "$dir" ] || return 0
    if [ ! -e "$dir/partial" ] && [ -f "$dir/config" ] && [ -d "$dir/rootfs" ]; then
        return 0
    fi
    log "Reliquat de création détecté ($dir) — nettoyage avant nouvelle tentative"
    lxc-destroy -n "$LXC_NAME" -P "$LXC_PATH" -f 2>/dev/null || rm -rf "$dir"
}

create_lxc() {
    clean_partial_lxc
    if [ -d "$LXC_PATH/$LXC_NAME/rootfs" ]; then
        log "LXC '$LXC_NAME' already exists — skipping debootstrap"
        return
    fi
    log "Creating unprivileged LXC '$LXC_NAME' (debian $DEBIAN_SUITE) ..."
    lxc-create -n "$LXC_NAME" -t download -P "$LXC_PATH" \
        -- --dist debian --release "$DEBIAN_SUITE" \
           --arch "$(dpkg --print-architecture)"
}

write_lxc_config() {
    log "Pinning network: $LXC_IP/24 on $LXC_BRIDGE (idmap 0->100000)"
    cat > "$LXC_PATH/$LXC_NAME/config" <<EOF
# SecuBox-managed — see secubox-jitsi / install-lxc.sh
lxc.uts.name = $LXC_NAME
lxc.net.0.type = veth
lxc.net.0.link = $LXC_BRIDGE
lxc.net.0.flags = up
lxc.net.0.ipv4.address = $LXC_IP/24
lxc.net.0.ipv4.gateway = $LXC_GW
lxc.net.0.name = eth0
lxc.rootfs.path = dir:$LXC_PATH/$LXC_NAME/rootfs
lxc.include = /usr/share/lxc/config/common.conf
lxc.idmap = u 0 100000 65536
lxc.idmap = g 0 100000 65536
lxc.apparmor.profile = generated
lxc.start.auto = 1
lxc.start.delay = 5
EOF
}

start_lxc() {
    [ "$(lxc_state)" = "running" ] && { log "Already running"; return; }
    log "Starting LXC '$LXC_NAME' ..."
    lxc-start -n "$LXC_NAME" -P "$LXC_PATH"
}

wait_for_network() {
    log "Waiting for LXC network ..."
    for _ in $(seq 1 30); do
        lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- ping -c1 -W1 "$LXC_GW" >/dev/null 2>&1 && return 0
        sleep 1
    done
    fail "LXC '$LXC_NAME' did not reach $LXC_GW within 30s"
}

ensure_resolv() {
    log "Seeding /etc/resolv.conf in LXC ..."
    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- sh -c '
        rm -f /etc/resolv.conf
        printf "nameserver 1.1.1.1\nnameserver 9.9.9.9\n" > /etc/resolv.conf
    '
}

# ── Jitsi install inside LXC (official apt repo) ──────────────────────────────
#
# The answers are PRESEEDED rather than corrected afterwards. jitsi-meet's
# postinst bakes the hostname into prosody's virtual host, jicofo's config, the
# videobridge's, and the generated nginx server block — all four in one pass. A
# hostname supplied after the fact would have to be chased through every one of
# them, and a missed occurrence produces a stack that starts cleanly and then
# refuses every conference.
#
# cert-choice = self-signed: TLS for meet.* is terminated by HAProxy on the
# host, which already holds the real certificate. A second ACME client inside
# the container would compete for the same name and the same :80 challenge
# path.
install_jitsi_in_lxc() {
    log "Installing Jitsi Meet in '$LXC_NAME' (domain: $JITSI_DOMAIN) ..."
    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- bash -e <<INNER
        set -euo pipefail
        export DEBIAN_FRONTEND=noninteractive

        apt-get update -q
        apt-get install -y --no-install-recommends \
            ca-certificates gnupg curl apt-transport-https debconf-utils \
            lua5.2 ssl-cert

        install -d -m 0755 /etc/apt/keyrings
        if [ ! -s /etc/apt/keyrings/jitsi.gpg ]; then
            curl -fsSL https://download.jitsi.org/jitsi-key.gpg.key \
                | gpg --dearmor -o /etc/apt/keyrings/jitsi.gpg
        fi
        cat > /etc/apt/sources.list.d/jitsi-stable.sources <<SRC
Types: deb
URIs: https://download.jitsi.org
Suites: stable/
Components:
Signed-By: /etc/apt/keyrings/jitsi.gpg
SRC

        # Preseed BEFORE the install: see the block comment above.
        debconf-set-selections <<SEL
jitsi-videobridge jitsi-videobridge/jvb-hostname string ${JITSI_DOMAIN}
jitsi-meet-web-config jitsi-meet/cert-choice select Generate a new self-signed certificate (You will later get a chance to obtain a Let's encrypt certificate)
jitsi-meet-prosody jitsi-videobridge/jvb-hostname string ${JITSI_DOMAIN}
SEL

        if ! dpkg -l jitsi-meet 2>/dev/null | grep -q '^ii'; then
            apt-get update -q
            apt-get install -y jitsi-meet
        else
            echo "jitsi-meet already installed — skipping apt install"
        fi

        systemctl daemon-reload
        for u in prosody jicofo jitsi-videobridge2; do
            systemctl enable "\$u" 2>/dev/null || true
        done
INNER
}

# ── Videobridge NAT wiring ───────────────────────────────────────────────────
#
# The one setting that decides whether media flows. The bridge advertises
# candidate addresses to peers; behind two NATs it sees only 10.100.0.190,
# which no external peer can route to. Both addresses are declared:
#
#   LOCAL   what the bridge is actually bound to (inside the LXC)
#   PUBLIC  what peers must send to (the ISP router's WAN address, which
#           forwards UDP/$JVB_PORT here)
#
# Without PUBLIC, calls negotiate and connect, then carry no audio or video —
# a failure that looks like an application bug and is a networking one.
#
# The public address is resolved once and RECORDED. It is deliberately not
# re-resolved on every run: a dynamic-IP change is a real event that should be
# handled explicitly (jitsictl set-public-ip), not silently papered over by a
# provisioning script that happens to run at boot.
configure_jvb_nat() {
    local public_ip="${SECUBOX_JITSI_PUBLIC_IP:-}"
    local recorded="$STATE_DIR/public-ip"

    if [ -z "$public_ip" ] && [ -s "$recorded" ]; then
        public_ip=$(cat "$recorded")
    fi
    if [ -z "$public_ip" ]; then
        public_ip=$(curl -fsS --max-time 10 https://api.ipify.org 2>/dev/null || true)
    fi
    if [ -z "$public_ip" ]; then
        log "WARNING: no public address resolved — the bridge will only serve LAN/mesh peers."
        log "         Set one later: jitsictl set-public-ip <addr>"
        return 0
    fi
    printf '%s\n' "$public_ip" > "$recorded"
    log "Videobridge NAT harvester: local=$LXC_IP public=$public_ip"

    lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- bash -e <<INNER
        set -euo pipefail
        # jitsi-videobridge2 2.3 ne LIVRE PLUS ce fichier (il n'installe que
        # jvb.conf), mais il le LIT toujours : son unité passe
        # -Dnet.java.sip.communicator.SC_HOME_DIR_LOCATION=/etc/jitsi et
        # SC_HOME_DIR_NAME=videobridge, ce qui pointe exactement ici. Le
        # créer est donc la manœuvre correcte — exiger qu'il préexiste faisait
        # échouer le provisionnement sur une pile par ailleurs saine.
        props=/etc/jitsi/videobridge/sip-communicator.properties
        [ -d /etc/jitsi/videobridge ] || { echo "jitsi-videobridge non installé"; exit 1; }
        touch "\$props"
        # Idempotent: drop any previous harvester lines, then re-add.
        sed -i '/NAT_HARVESTER_LOCAL_ADDRESS/d;/NAT_HARVESTER_PUBLIC_ADDRESS/d' "\$props"
        {
            echo "org.ice4j.ice.harvest.NAT_HARVESTER_LOCAL_ADDRESS=${LXC_IP}"
            echo "org.ice4j.ice.harvest.NAT_HARVESTER_PUBLIC_ADDRESS=${public_ip}"
        } >> "\$props"
        systemctl restart jitsi-videobridge2 2>/dev/null || true
INNER
}

mark_provisioned() {
    date -Is > "$SENTINEL"
    log "Provisioned marker: $SENTINEL"
}

main() {
    require_cmds
    ensure_dirs
    ensure_bridge
    ensure_masquerade
    create_lxc
    write_lxc_config
    start_lxc
    wait_for_network
    ensure_resolv
    install_jitsi_in_lxc
    configure_jvb_nat
    mark_provisioned
    log "Done. Web tier: http://${LXC_IP}:${WEB_PORT}/  ·  media: UDP/${JVB_PORT}"
    log "Reminder: UDP/${JVB_PORT} must be forwarded from the ISP router to this host,"
    log "          and DNAT'd to ${LXC_IP} (see conf/jitsi.nft)."
}

main "$@"
