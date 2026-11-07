#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: image — arbitrages de services communs a toutes les images
#
# Partage par build-image.sh et build-rpi-usb.sh : une copie par chemin
# divergerait, et la correction ne vaudrait que la ou on vient de regarder.

set -euo pipefail
ROOTFS="${1:?usage: $0 <rootfs>}"
[ -d "$ROOTFS" ] || { echo "[services] rootfs introuvable : $ROOTFS" >&2; exit 1; }

# ── dnsmasq : masque, car il confisque le port 53 ────────────────────────
#
# CE QUI SE PASSAIT. Le paquet `dnsmasq` livre un service systeme active par
# defaut et SANS configuration : il se pose donc sur 0.0.0.0:53 et [::]:53,
# TCP et UDP, toutes interfaces confondues. Mesure sur une image neuve, il
# demarrait a 16:24:51 et prenait tout. Deux secondes plus tard :
#
#   unbound : can't bind socket: Address already in use for ::1 port 53
#   lxc-net : dnsmasq: failed to create listening socket for 10.0.3.1
#
# Trois unites tombaient d'un coup — unbound, lxc-net, et
# secubox-jellyfin-provision par cascade (lxc-create sans pont reseau).
# `unbound-checkconf` ne signalait rien : ce n'etait pas une configuration
# fautive mais un conflit de port inscrit dans l'image (#1308).
#
# POURQUOI MASQUER PLUTOT QUE RECONFIGURER. unbound EST le resolveur du parc
# (Vortex DNS) ; dnsmasq n'y sert qu'a du DHCP sur une interface precise, via
# des instances lancees par les modules qui en ont besoin — lxc-net le fait
# deja, avec son propre processus sur 10.0.3.1. Le service systeme global
# n'a donc aucun role, il ne fait que prendre la place.
#
# POURQUOI PAS `dnsmasq-base` SEUL. Debian separe bien le binaire
# (dnsmasq-base) du service (dnsmasq), et n'installer que le premier serait
# plus propre. Mais secubox-vortex-dns et secubox-nac declarent tous deux
# `Depends: dnsmasq` : apt le reinstallerait. Corriger ces dependances est
# possible mais demande de verifier qu'aucun des deux n'utilise vraiment
# dnsmasq.service — a trancher separement.
#
# gk2, en production, le tient masque depuis toujours. Ce masquage
# n'appartenait a aucun paquet : sedimentation, comme les repertoires de
# #1307 et les manifestes de cycle de vie. On le grave ici.
#
# Verifie en direct sur la VM trixie : unbound failed -> active (127.0.0.1:53
# et [::1]:53), lxc-net failed -> active (dnsmasq sur 10.0.3.1:53), et la
# resolution DNS continue de repondre.
if [ -e "${ROOTFS}/usr/lib/systemd/system/dnsmasq.service" ] \
   || [ -e "${ROOTFS}/lib/systemd/system/dnsmasq.service" ]; then
    install -d "${ROOTFS}/etc/systemd/system"
    ln -sf /dev/null "${ROOTFS}/etc/systemd/system/dnsmasq.service"
    echo "[services] dnsmasq.service masque — unbound garde le port 53"
else
    echo "[services] dnsmasq.service absent, rien a masquer"
fi

# ── Provisionnement lourd : jamais sur un live (#3554) ───────────────────
#
# Un live écrit en RAM. Mesuré sur la VM : en 4 minutes les LXC jellyfin,
# voicestudio et picobrew remplissent l'overlay (2,8 Go sur 3,9), et 4 Go de
# mémoire ne suffisent plus à démarrer. La condition ne vaut que sur l'overlay :
# le système installé garde son provisionnement.
for unite in "${ROOTFS}"/usr/lib/systemd/system/secubox-*-provision.service; do
    [ -e "$unite" ] || continue
    d="${ROOTFS}/etc/systemd/system/$(basename "$unite").d"
    install -d "$d"
    printf '[Unit]\nConditionPathExists=!/run/live/overlay/work\n' > "$d/secubox-live.conf"
    echo "[services] $(basename "$unite") : sauté sur un live"
done
