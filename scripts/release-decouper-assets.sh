#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
#
# Découpe les images compressées trop grosses pour une release GitHub (limite : 2 Gio par fichier,
# « size must be less than 2147483648 », alpha.12 #2427).
#
#   release-decouper-assets.sh <dossier>... [--max-mo N]
#
# Pour chaque <dossier>/*.img.gz et *.img.xz plus gros que N Mo (défaut 1900) :
#   - écrit <fichier>.assembled.sha256 : la somme du fichier REASSEMBLÉ, au format `sha256sum`
#     (à vérifier après `cat <fichier>.part* > <fichier>`) ;
#   - le découpe en <fichier>.part00, .part01… (même convention que build-all-live-usb.yml) ;
#   - supprime l'original, devenu inutile (il ne sera pas publié).
# Les fichiers plus petits ne sont pas touchés. Idempotent : sans fichier trop gros, ne fait rien.
set -euo pipefail

max_mo=1900
dossiers=()
while [ $# -gt 0 ]; do
  case "$1" in
    --max-mo) max_mo="${2:?--max-mo demande une valeur}"; shift 2 ;;
    -h|--help) sed -n 7,19p "$0"; exit 0 ;;
    *) dossiers+=("$1"); shift ;;
  esac
done
[ "${#dossiers[@]}" -gt 0 ] || { echo "usage: $0 <dossier>... [--max-mo N]" >&2; exit 2; }
case "$max_mo" in ''|*[!0-9]*) echo "--max-mo : entier attendu" >&2; exit 2 ;; esac
limite=$(( max_mo * 1024 * 1024 ))

n=0
for d in "${dossiers[@]}"; do
  [ -d "$d" ] || continue
  for f in "$d"/*.img.gz "$d"/*.img.xz; do
    [ -f "$f" ] || continue
    taille=$(stat -c %s "$f")
    [ "$taille" -gt "$limite" ] || continue
    nom=$(basename "$f")
    echo "découpage de $nom ($(( taille / 1048576 )) Mo > ${max_mo} Mo)"
    ( cd "$d" && sha256sum "$nom" > "$nom.assembled.sha256" )
    split -b "${max_mo}M" -a 2 -d "$f" "$f.part"
    rm -f "$f"
    n=$(( n + 1 ))
  done
done
echo "fichiers découpés : $n"
