#!/bin/bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
#
# live-initrd-modules.sh INITRD RACINE — rend un initrd capable de monter le live (#3079) :
# ajoute squashfs et overlay, lève la liste noire de squashfs.
#
# L'initrd d'une image eMMC ne sait monter qu'une racine ext4 ; live-boot doit monter le
# filesystem.squashfs téléchargé sous un overlay. Sans ces modules : « request_module
# fs-squashfs succeeded, but still no fs? » puis BOOT FAILED. Les modules sont pris dans
# RACINE/lib/modules/<version> (rootfs ou squashfs monté du live), modules.dep recalculé,
# l'initrd réécrit à sa place (archives « early » non compressées conservées en tête).
set -euo pipefail

initrd="${1:-}"; racine="${2:-}"
die() { echo "[live-initrd] ERREUR : $*" >&2; exit 1; }
[ -s "$initrd" ] || die "initrd introuvable : $initrd"
[ -d "$racine/lib/modules" ] || die "pas de lib/modules sous $racine"
for c in unmkinitramfs cpio zstd depmod; do command -v "$c" >/dev/null || die "outil manquant : $c"; done

w="$(mktemp -d)"
trap 'rm -rf "$w"' EXIT
unmkinitramfs "$initrd" "$w/ird"
main="$w/ird"; [ -d "$w/ird/main" ] && main="$w/ird/main"

# Version : celle que l'initrd porte déjà et que la racine fournit ; sinon la plus récente de la racine.
v=""
for d in "$main"/lib/modules/* "$main"/usr/lib/modules/*; do
    [ -d "$d" ] && [ -d "$racine/lib/modules/${d##*/}" ] && v="${d##*/}"
done
[ -n "$v" ] || v="$(find "$racine/lib/modules" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort -V | tail -n1)"
[ -n "$v" ] || die "aucune version de modules sous $racine"

for m in fs/squashfs/squashfs fs/overlayfs/overlay; do
    f="$(find "$racine/lib/modules/$v/kernel/${m%/*}" -maxdepth 1 -name "${m##*/}.ko*" 2>/dev/null | head -n1)"
    if [ -z "$f" ]; then
        grep -q "kernel/$m.ko" "$racine/lib/modules/$v/modules.builtin" 2>/dev/null && continue
        die "module ${m##*/} absent de $racine/lib/modules/$v"
    fi
    mkdir -p "$main/lib/modules/$v/kernel/${m%/*}"
    cp "$f" "$main/lib/modules/$v/kernel/${m%/*}/"
done
for x in modules.builtin modules.builtin.modinfo modules.order; do
    [ -e "$main/lib/modules/$v/$x" ] || [ ! -e "$racine/lib/modules/$v/$x" ] || cp "$racine/lib/modules/$v/$x" "$main/lib/modules/$v/"
done
depmod -b "$main" "$v"

# secubox-hardening met squashfs en liste noire (secubox-blacklist.conf, recopié dans l'initrd) :
# le noyau le demande par l'alias fs-squashfs, refusé. Le live, lui, EST un squashfs : seule
# cette ligne est levée, dans l'initrd du live seulement ; le système installé garde la sienne.
for f in "$main"/etc/modprobe.d/*.conf "$main"/usr/lib/modprobe.d/*.conf; do
    [ -f "$f" ] || continue
    sed -i -E '/^[[:space:]]*(blacklist|install)[[:space:]]+squashfs([[:space:]]|$)/d' "$f"
done

{
    for e in "$w/ird"/early*; do
        [ -d "$e" ] || continue
        (cd "$e" && find . | LC_ALL=C sort | cpio -o -H newc --quiet)
    done
    (cd "$main" && find . | LC_ALL=C sort | cpio -o -H newc --quiet | zstd -q -T0 -10)
} > "$w/initrd.new"
cp "$w/initrd.new" "$initrd"
echo "[live-initrd] squashfs et overlay ajoutés ($v)"
