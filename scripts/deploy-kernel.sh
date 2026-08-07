#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: deploy-kernel.sh — installer un noyau sur une board
#
# POURQUOI CE SCRIPT EXISTE
#
# `dpkg -i linux-image-*.deb` ECHOUE sur les boards SecuBox :
#
#   unable to make backup link of './boot/System.map-6.12.85'
#   before installing new version: Operation not permitted
#
# `/boot` est une partition **VFAT** (ESP, /dev/mmcblk0p1) et VFAT n'a pas de
# liens durs — or dpkg en a besoin pour remplacer un fichier atomiquement.
# L'echec est propre (le systeme reste intact), mais il est definitif : aucun
# noyau ne s'installera jamais par dpkg tant que /boot sera en VFAT.
#
# Ce script fait donc l'installation a la main, dans le bon ordre, avec une
# sauvegarde prealable et une verification apres coup.
#
# PRUDENCE PAR DEFAUT : sans --apply, il n'ecrit rien et montre ce qu'il ferait.
#
# Usage :
#   bash scripts/deploy-kernel.sh <image.deb> [root@host] [--apply]

set -euo pipefail

DEB="${1:-}"
HOST="${2:-root@192.168.1.200}"
APPLY="${3:-}"

log()  { printf '\033[1;36m[%s] %s\033[0m\n' "$(date '+%H:%M:%S')" "$*"; }
warn() { printf '\033[1;33m[%s] %s\033[0m\n' "$(date '+%H:%M:%S')" "$*"; }
fail() { printf '\033[1;31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }

[ -f "$DEB" ] || fail "paquet introuvable : $DEB (usage: $0 <image.deb> [host] [--apply])"

# La version du noyau (uname -r) se lit dans le chemin des modules embarques.
REL=$(dpkg -c "$DEB" | grep -oE 'lib/modules/[^/]+' | cut -d/ -f3 | sort -u | tail -1)
[ -n "$REL" ] || fail "impossible de determiner la version du noyau depuis $DEB"
PKGVER=$(dpkg -f "$DEB" Version 2>/dev/null || echo "?")

log "paquet   : $(basename "$DEB")"
log "version  : $PKGVER   (release $REL)"
log "cible    : $HOST"

if [ "$APPLY" != "--apply" ]; then
    warn "SIMULATION — rien ne sera ecrit. Ajoutez --apply pour installer."
fi

# ── 1. verifications prealables sur la board ────────────────────────────────
log "verification de la cible"
ssh "$HOST" "set -e
    findmnt -no FSTYPE /boot | grep -q vfat && echo '  /boot est en VFAT — installation manuelle requise (attendu)'
    free=\$(df -m /boot | awk 'NR==2{print \$4}')
    [ \"\$free\" -ge 80 ] || { echo \"  /boot: seulement \${free} Mo libres — insuffisant\"; exit 1; }
    echo \"  /boot: \${free} Mo libres\"
    echo \"  noyau courant: \$(uname -r)\"
" || fail "verifications prealables echouees"

[ "$APPLY" = "--apply" ] || { log "simulation terminee"; exit 0; }

# ── 2. sauvegarde ───────────────────────────────────────────────────────────
#
# Meme chaine de version = memes chemins : le nouveau noyau ECRASE l'ancien,
# modules compris. Sans cette sauvegarde, il n'y aurait aucun retour arriere.
log "sauvegarde du noyau en place"
ssh "$HOST" "set -e
    B=/data/backup/kernel-\$(uname -r)-\$(date +%Y%m%d-%H%M%S)
    mkdir -p \"\$B\"
    cp -a /boot/vmlinuz-$REL /boot/initrd.img-$REL \"\$B\"/ 2>/dev/null || true
    cp -a /boot/extlinux/extlinux.conf \"\$B\"/ 2>/dev/null || true
    [ -d /lib/modules/$REL ] && tar czf \"\$B/lib-modules-$REL.tar.gz\" -C /lib/modules $REL
    echo \"  sauvegarde: \$B\"
"

# ── 3. transfert et extraction ──────────────────────────────────────────────
log "transfert du paquet"
scp -q "$DEB" "$HOST:/tmp/$(basename "$DEB")"

# L'image BRUTE ne se trouve pas dans le paquet : elle vient de l'arbre de
# compilation. Sans elle, extlinux boote un vmlinuz gzip que booti refuse.
IMGNAME="${PKGVER##*-}"
RAW_IMAGE="${RAW_IMAGE:-$(dirname "$DEB")/../linux-$REL/arch/arm64/boot/Image}"
RAW_IMAGE_REMOTE="/tmp/Image-$IMGNAME"
if [ -f "$RAW_IMAGE" ]; then
    log "transfert de l'image brute ($(du -h "$RAW_IMAGE" | cut -f1))"
    scp -q "$RAW_IMAGE" "$HOST:$RAW_IMAGE_REMOTE"
else
    warn "IMAGE BRUTE INTROUVABLE ($RAW_IMAGE) — extlinux ne pourra PAS demarrer"
    warn "ce noyau : booti n'accepte pas un vmlinuz compresse. Passez RAW_IMAGE=."
    RAW_IMAGE=""
fi

log "extraction et mise en place"
ssh "$HOST" "set -e
    rm -rf /tmp/kdeploy && mkdir -p /tmp/kdeploy
    dpkg-deb -x /tmp/$(basename "$DEB") /tmp/kdeploy

    # Modules d'abord : l'initrd se construit a partir d'eux.
    rm -rf /lib/modules/$REL
    cp -a /tmp/kdeploy/lib/modules/$REL /lib/modules/
    depmod -a $REL

    # Puis /boot. cp et non install/link : VFAT ne connait pas les liens durs.
    cp -f /tmp/kdeploy/boot/vmlinuz-$REL /boot/vmlinuz-$REL

    # ── IMAGE BRUTE, indispensable ──────────────────────────────────────────
    #
    # `vmlinuz-*` est une image COMPRESSEE gzip. `booti` (arm64) ne sait pas la
    # demarrer : l'entree extlinux qui pointait dessus echouait EN SILENCE et
    # U-Boot retombait sur l'entree suivante — un noyau de juin. Trois
    # deploiements successifs n'ont ainsi jamais pris, alors que le fichier
    # installe etait bien le bon (md5 identique).
    #
    # Le paquet linux-image ne contient que vmlinuz ; l'image brute vient de
    # l'arbre de compilation. Sans elle, ce script installe un noyau qui ne
    # demarrera pas.
    if [ -n "${RAW_IMAGE:-}" ] && [ -f "$RAW_IMAGE_REMOTE" ]; then
        cp -f "$RAW_IMAGE_REMOTE" /boot/Image-$IMGNAME
        echo "  image brute: /boot/Image-$IMGNAME"
    fi
    for f in System.map config; do
        [ -f \"/tmp/kdeploy/boot/\$f-$REL\" ] && cp -f \"/tmp/kdeploy/boot/\$f-$REL\" \"/boot/\$f-$REL\" || true
    done

    # L'initrd doit etre regenere : il embarque les modules, qui viennent de
    # changer. Un initrd de l'ancien noyau ne trouverait pas ses modules.
    update-initramfs -c -k $REL 2>&1 | tail -2 || update-initramfs -u -k $REL 2>&1 | tail -2
    rm -rf /tmp/kdeploy
"

# ── 4. verification ─────────────────────────────────────────────────────────
log "verification"
ssh "$HOST" "set -e
    echo \"  vmlinuz : \$(stat -c %y /boot/vmlinuz-$REL | cut -d. -f1)\"
    echo \"  initrd  : \$(stat -c %y /boot/initrd.img-$REL | cut -d. -f1)\"
    echo \"  modules : \$(find /lib/modules/$REL -name '*.ko*' | wc -l) modules\"
    echo \"  entree de demarrage par defaut :\"
    grep -A3 \"^DEFAULT\" /boot/extlinux/extlinux.conf | head -2 | sed 's/^/    /'
"

# Rappel : l'entree extlinux par defaut doit pointer sur l'image BRUTE.
ssh "$HOST" "grep -A3 \"^DEFAULT\" /boot/extlinux/extlinux.conf | head -4 | sed 's/^/    /'" 2>/dev/null || true

log "installe. Le noyau ne sera actif qu'apres REDEMARRAGE."
warn "Verifiez que l'entree DEFAULT d'extlinux pointe sur /Image-* (brute),"
warn "PAS sur /vmlinuz-* : booti n'accepte pas une image compressee, l'entree"
warn "echoue en silence et U-Boot retombe sur la suivante."
warn "En cas d'echec au demarrage : console serie, choisir une entree de repli"
warn "dans le menu (TIMEOUT 3 s), puis restaurer depuis /data/backup/."
