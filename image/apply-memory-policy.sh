#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: image — politique memoire commune a toutes les images
#
# POURQUOI CE SCRIPT EXISTE. La meme politique doit valoir pour les images
# Raspberry Pi (build-rpi-usb.sh) et pour les autres (build-image.sh). Deux
# copies divergeraient : la premiere correction ne serait appliquee qu'a un
# seul chemin, et le defaut survivrait la ou personne ne regarde. C'est
# exactement ce qui vient de se passer avec le filtrage par profil.
#
# CE QU'IL POSE.
#
# 1. zram — un swap compresse en RAM. Sans swap du tout, l'epuisement
#    memoire frappe la machine entiere : le noyau vit, repond au ping, sshd
#    et nginx acceptent le TCP, mais plus aucun fork() n'aboutit ; un shell
#    s'ouvre sur la console puis la premiere commande se fige. Constate sur
#    un rpi400 (#1308). zram plutot qu'un fichier d'echange parce que le
#    stockage peut etre une carte SD : y ecrire du swap l'use et ajoute des
#    latences qui AGGRAVENT le blocage. zram coute du CPU et zero ecriture.
#
# 2. secubox.slice — un plafond memoire COLLECTIF. Les modules sont des
#    interpretes Python persistants ; sur l'image livree, 140 unites se
#    levaient au demarrage et NEUF portaient une borne. Les borner une par
#    une demanderait de toucher 140 paquets et de deviner autant de chiffres
#    inconnus. La slice plafonne l'agregat, ce qui suffit : la pression reste
#    CONFINEE, le noyau reclame et au besoin tue a l'interieur, pendant que
#    systemd, sshd et la console gardent leur part. On perd un module ; on ne
#    perd plus la machine.
#
#    Les bornes sont en POURCENTAGE, resolus au demarrage : la meme image se
#    borne correctement sur un rpi400 a 4 Go comme sur une VM a 16.
#    MemoryHigh est le frein (reclamation soutenue), MemoryMax le mur (OOM
#    dans la slice) ; l'ecart entre les deux laisse au noyau une chance de
#    recuperer avant de tuer quoi que ce soit.
#
# Ce n'est PAS un permis de tout lancer : le filtrage par profil reste la
# vraie limite. Ceci est le filet, pas le plancher.

set -euo pipefail

ROOTFS="${1:?usage: $0 <rootfs>}"
[ -d "$ROOTFS" ] || { echo "[memoire] rootfs introuvable : $ROOTFS" >&2; exit 1; }

install -d "${ROOTFS}/etc/systemd" "${ROOTFS}/etc/sysctl.d" "${ROOTFS}/etc/systemd/system"

cat > "${ROOTFS}/etc/systemd/zram-generator.conf" <<'ZRAM'
[zram0]
zram-size = ram
compression-algorithm = zstd
swap-priority = 100
fs-type = swap
ZRAM

# Pages froides poussees plus tot vers zram : la compression est bon marche,
# la penurie ne l'est pas. Valeurs usuelles pour un swap compresse.
cat > "${ROOTFS}/etc/sysctl.d/90-secubox-zram.conf" <<'SYSCTL'
vm.swappiness = 150
vm.page-cluster = 0
SYSCTL

cat > "${ROOTFS}/etc/systemd/system/secubox.slice" <<'SLICE'
[Unit]
Description=SecuBox — modules, sous plafond memoire collectif
Before=slices.target

[Slice]
MemoryAccounting=yes
MemoryHigh=60%
MemoryMax=75%
SLICE

# Rattachement des unites. Un drop-in par unite : systemd n'assigne pas de
# slice par convention de nom. Genere ici plutot que livre dans 140 paquets —
# la regle est la meme pour tous, et la dupliquer la rendrait intouchable.
# Le drop-in d'un modele `@.service` vaut pour toutes ses instances.
rattachees=0
for u in "${ROOTFS}"/lib/systemd/system/secubox-*.service \
         "${ROOTFS}"/usr/lib/systemd/system/secubox-*.service; do
  [ -e "$u" ] || continue
  n=$(basename "$u")
  install -d "${ROOTFS}/etc/systemd/system/${n}.d"
  cat > "${ROOTFS}/etc/systemd/system/${n}.d/50-secubox-memoire.conf" <<'DROPIN'
[Service]
Slice=secubox.slice
DROPIN
  rattachees=$((rattachees + 1))
done

echo "[memoire] zram + secubox.slice poses, ${rattachees} unite(s) rattachee(s)"
