#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
#
# release-envoyer.sh VERSION — crée (ou repasse) la release en BROUILLON, envoie les fichiers de release/ un par un avec reprises,
# vérifie que chacun est sur la release, puis la publie. Au moindre fichier manquant elle reste en brouillon et le script échoue (#2719).
# Partagé par release.yml (étape create-release) et release-completer.yml (reprise d'une release incomplète à partir des artefacts d'un run).
# Variables : GH_TOKEN (gh). Attend release/RELEASE_NOTES.md et les dossiers release/images, release/live-usb.
set -euo pipefail
VERSION="${1:?version manquante (ex. v3.0.0-alpha.17)}"
PRE=""
case "$VERSION" in *alpha*|*beta*|*rc*) PRE="--prerelease" ;; esac

# BROUILLON D'ABORD (#2719) : une release incomplete n'est visible de personne. Elle n'est publiee qu'apres le dernier envoi
# verifie ; au moindre fichier manquant elle reste en brouillon et le job echoue. Les .deb de build-packages sont deja sur la
# release (#1491) : on ne les touche pas.
if gh release view "$VERSION" >/dev/null 2>&1; then
  gh release edit "$VERSION" --draft --title "SecuBox-DEB $VERSION" --notes-file release/RELEASE_NOTES.md $PRE
else
  gh release create "$VERSION" --draft --verify-tag --title "SecuBox-DEB $VERSION" --notes-file release/RELEASE_NOTES.md $PRE
fi

# UN FICHIER A LA FOIS, avec reprises. softprops/action-gh-release envoyait tout en parallele : sur des images de 1 a 2 Go,
# « Upload body timed out due to inactivity » puis « error updating release asset metadata : Not Found » (alpha.16 et alpha.17).
# --clobber remplace un fichier deja present (relance) sans le supprimer d'abord.
# MEME ORDRE qu'avant : a nom egal, le DERNIER fichier envoye reste (live-usb/ apres images/), comme pour SHA256SUMS. Compressees
# SEULEMENT (#1507) : l'image brute fait plus de 2 Go. Parties des images de plus de 1900 Mo (limite GitHub, #2427) : .part*
shopt -s nullglob
FICHIERS=(
  release/images/*.img.gz
  release/images/*.img.xz
  release/images/*.part*
  release/images/*.assembled.sha256
  release/live-usb/*.part*
  release/live-usb/*.assembled.sha256
  release/live-usb/*.img.gz
  release/live-usb/*.img.xz
  release/live-usb/*.sha256
  release/create-qemu-arm64-vm.sh
  release/create-vbox-vm.sh
  release/SHA256SUMS
  release/SHA256SUMS.gpg
)
echec=0
ENVOYES=()
for f in "${FICHIERS[@]}"; do
  [ -f "$f" ] || continue
  ok=0
  for i in 1 2 3 4; do
    if gh release upload "$VERSION" "$f" --clobber; then ok=1; break; fi
    echo "::warning::envoi de $(basename "$f") echoue (essai $i sur 4)"
    sleep $((i * 20))
  done
  if [ "$ok" = 1 ]; then ENVOYES+=("$f"); else echo "::error::envoi definitivement echoue : $f"; echec=1; fi
done

# Chaque fichier envoye doit etre sur la release.
publies="$(gh release view "$VERSION" --json assets --jq '.assets[].name')"
for f in "${ENVOYES[@]}"; do
  n="$(basename "$f")"
  printf '%s\n' "$publies" | grep -qxF "$n" || { echo "::error::fichier manquant sur la release : $n"; echec=1; }
done

if [ "$echec" != 0 ]; then
  echo "::error::release $VERSION laissee en BROUILLON : des fichiers manquent. Relancer le job (les fichiers deja envoyes sont remplaces)."
  exit 1
fi
gh release edit "$VERSION" --draft=false $PRE
