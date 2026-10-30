#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: secubox-clamav :: install-lxc.sh (#1912)
#
# Crée (idempotent) le LXC `clamav` : Debian (dernière stable) non privilégié, IP fixe sur br-lxc,
# clamd en TCP sur cette IP SEULEMENT, base téléchargée une première fois. Le conteneur ne
# démarre PAS au boot (lxc.start.auto = 0) : clamavctl le réveille à la demande.
# Modèle : packages/secubox-ytsas/lxc/install-lxc.sh.
set -euo pipefail
# SUITE DEBIAN DU CONTENEUR (#3285) : la dernière stable, c'est-à-dire celle de
# l'hôte (une box est installée sur la stable courante) ; repli trixie si l'hôte
# n'est pas une Debian lisible. Surcharge : SECUBOX_DEBIAN_SUITE.
suite_debian_hote() {
    local f="${SECUBOX_OS_RELEASE:-/etc/os-release}" id="" code=""
    if [ -r "$f" ]; then
        # shellcheck source=/dev/null
        id="$(. "$f" && printf '%s' "${ID:-}")"
        # shellcheck source=/dev/null
        code="$(. "$f" && printf '%s' "${VERSION_CODENAME:-}")"
    fi
    case "$code" in ""|*[!a-z]*) code="" ;; esac
    if [ "$id" = debian ] && [ -n "$code" ]; then
        printf '%s\n' "$code"
    else
        printf 'trixie\n'
    fi
}

readonly DEBIAN_SUITE="${SECUBOX_DEBIAN_SUITE:-$(suite_debian_hote)}"
readonly LXC_NAME="${SECUBOX_CLAMAV_NOM:-clamav}"
readonly LXC_IP="${SECUBOX_CLAMAV_IP:-10.100.0.220}"
readonly LXC_PATH="${SECUBOX_CLAMAV_PATH:-/data/lxc}"
readonly LXC_BRIDGE="${SECUBOX_LXC_BRIDGE:-br-lxc}"
readonly LXC_GW="${SECUBOX_LXC_GW:-10.100.0.1}"
readonly LXC_VETH="veth-clamav0"
readonly LXC_ROOT_UID="${SECUBOX_LXC_ROOT_UID:-100000}"
readonly PORT="${SECUBOX_CLAMAV_PORT:-3310}"
readonly STATE_DIR="/var/lib/secubox/clamav"
readonly SENTINEL="$STATE_DIR/.lxc-provisioned"
log() { printf '[clamav-install] %s\n' "$*"; }
la()  { lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- "$@"; }

# SYSTEMD >= 257 (trixie) DANS UN LXC NON PRIVILÉGIÉ : ImportCredential= y échoue
# (243/CREDENTIALS) et laisse journald, sysctl et tmpfiles en échec. Vidé par
# drop-in, seulement si le conteneur a ce systemd (#3274, #3285). Idempotent.
# lxc_sans_credentials <nom> <chemin-lxc>
lxc_sans_credentials() {
    # shellcheck disable=SC2016  # expansion voulue DANS le conteneur
    lxc-attach -n "$1" -P "$2" -- sh -c '
        v=$(systemctl --version 2>/dev/null | awk "NR==1{print \$2}")
        case "$v" in ""|*[!0-9]*) exit 0 ;; esac
        [ "$v" -ge 257 ] || exit 0
        for u in systemd-journald systemd-sysctl systemd-tmpfiles-setup systemd-tmpfiles-clean; do
            mkdir -p "/etc/systemd/system/$u.service.d"
            printf "%s\n" "# SecuBox #3274 : LXC non privilégié, pas de credentials systemd" \
                "[Service]" "ImportCredential=" > "/etc/systemd/system/$u.service.d/secubox-lxc.conf"
        done
        systemctl daemon-reload
        systemctl restart systemd-journald.service systemd-sysctl.service \
            systemd-tmpfiles-setup.service 2>/dev/null || true
    '
}

mkdir -p "$STATE_DIR"
if [ ! -f "$SENTINEL" ]; then
  lxc-create -n "$LXC_NAME" -t download -P "$LXC_PATH" -- \
    --dist debian --release "$DEBIAN_SUITE" --arch "$(dpkg --print-architecture)"
  if ! grep -q '^lxc.idmap' "$LXC_PATH/$LXC_NAME/config"; then
    printf 'lxc.idmap = u 0 %s 65536\nlxc.idmap = g 0 %s 65536\n' "$LXC_ROOT_UID" "$LXC_ROOT_UID" \
      >> "$LXC_PATH/$LXC_NAME/config"
  fi
  # Le modèle de création pose déjà un bloc lxc.net.0 : on le REMPLACE, jamais on n'en ajoute un
  # second (deux `lxc.net.0.type` font avorter lxc-start).
  sed -i '/^lxc\.net\.0\./d' "$LXC_PATH/$LXC_NAME/config"
  cat >> "$LXC_PATH/$LXC_NAME/config" <<CFG
lxc.net.0.type = veth
lxc.net.0.link = $LXC_BRIDGE
lxc.net.0.flags = up
lxc.net.0.veth.pair = $LXC_VETH
lxc.net.0.ipv4.address = $LXC_IP/24
lxc.net.0.ipv4.gateway = $LXC_GW

# ÉVEILLÉ À LA DEMANDE (#1912) : jamais au démarrage de la box ; clamavctl wake / sleep.
lxc.start.auto = 0

# Budget mémoire (#496) — alloué SEULEMENT pendant que le conteneur est éveillé. clamd avec
# main+daily demande ~1,2–1,5 Go ; ConcurrentDatabaseReload est coupé pour ne pas doubler.
lxc.cgroup2.memory.high = 1400M
lxc.cgroup2.memory.max = 1800M
CFG
  # Le rootfs déballé est à l'uid 0 de l'HÔTE ; l'idmap veut 100000 (cf. ytsas, #1308).
  if [ "$(stat -c %u "$LXC_PATH/$LXC_NAME/rootfs")" = "0" ]; then
    chown -R "$LXC_ROOT_UID:$LXC_ROOT_UID" "$LXC_PATH/$LXC_NAME/rootfs"
    chown "$LXC_ROOT_UID:$LXC_ROOT_UID" "$LXC_PATH/$LXC_NAME"
  fi
  lxc-start -n "$LXC_NAME" -P "$LXC_PATH" -d
  sleep 6
  lxc_sans_credentials "$LXC_NAME" "$LXC_PATH"
  la sh -c 'rm -f /etc/resolv.conf; printf "nameserver 1.1.1.1\nnameserver 9.9.9.9\n" > /etc/resolv.conf'
  la apt-get update
  la env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    clamav-daemon clamav-freshclam ca-certificates
  touch "$SENTINEL"
else
  log "déjà provisionné ; configuration et base remises à jour"
  lxc-info -P "$LXC_PATH" -n "$LXC_NAME" -sH | grep -q RUNNING || lxc-start -n "$LXC_NAME" -P "$LXC_PATH" -d && sleep 6
fi

# clamd : TCP sur l'IP du conteneur SEULEMENT (jamais 0.0.0.0), idempotent.
#
# SUR DEBIAN, clamd EST DÉMARRÉ PAR ACTIVATION DE SOCKET (clamav-daemon.socket) et, dans ce cas,
# IGNORE `TCPSocket` de clamd.conf : il ne sert que les sockets que systemd lui passe. L'écoute
# TCP se déclare donc sur l'unité socket (vérifié sur gk2 : sans cela, rien n'écoute sur 3310 et
# le premier client attend jusqu'à l'expiration). FreeBind : l'adresse peut précéder l'interface.
la sh -c 'mkdir -p /etc/systemd/system/clamav-daemon.socket.d && cat > /etc/systemd/system/clamav-daemon.socket.d/tcp.conf' <<CONF
[Socket]
ListenStream=
ListenStream=/run/clamav/clamd.ctl
ListenStream=$LXC_IP:$PORT
FreeBind=true
CONF
la sh -c "grep -q '^# secubox-clamav' /etc/clamav/clamd.conf || cat >> /etc/clamav/clamd.conf" <<CONF
# secubox-clamav (#1912) — réglages posés par install-lxc.sh
ConcurrentDatabaseReload no
MaxThreads 4
StreamMaxLength 50M
MaxFileSize 50M
CONF
la systemctl daemon-reload
# Première base : indispensable, clamd refuse de démarrer sans (ConditionPathExistsGlob).
la systemctl stop clamav-freshclam 2>/dev/null || true
if ! la sh -c 'ls /var/lib/clamav/daily.c[lv]d >/dev/null 2>&1'; then
  log "téléchargement de la base de signatures (plusieurs minutes)…"
  la freshclam --quiet
fi
la systemctl enable clamav-daemon.socket clamav-daemon clamav-freshclam
la systemctl restart clamav-daemon.socket clamav-daemon
log "clamd prêt sur $LXC_IP:$PORT ; on rendort le conteneur"
lxc-stop -n "$LXC_NAME" -P "$LXC_PATH" -t 30 || true
