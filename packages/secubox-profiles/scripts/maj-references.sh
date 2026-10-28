#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
#
# SecuBox-Deb :: profiles — met à jour les profils de référence NON MODIFIÉS de /etc/secubox/profiles (#3218).
#
# Le postinst ne semait les profils qu'à la première installation : une mise à jour du paquet ne changeait jamais
# /etc/secubox/profiles/minimal.toml, et `secubox-profilectl apply --profile minimal` appliquait l'ANCIEN profil (sur
# gk5, il aurait arrêté le maillage). Règle : une copie identique, octet pour octet, à une version déjà LIVRÉE de ce
# profil (empreintes-livrees.txt, tirées de l'historique git) n'a pas été modifiée par l'opérateur : on la remplace.
# Une copie modifiée (à la main, ou réécrite par le panneau) est gardée ; la nouvelle référence est posée à côté en
# <nom>.toml.dpkg-dist (hors du motif *.toml que lisent la CLI et le panneau) et le journal de dpkg le dit.
#
# Usage : maj-references.sh [SOURCE] [CIBLE] [EMPREINTES]   (PROPRIO=utilisateur:groupe pour chown, postinst seulement)
set -euo pipefail

SOURCE="${1:-/usr/share/secubox/profiles}"
CIBLE="${2:-/etc/secubox/profiles}"
EMPREINTES="${3:-${SOURCE}/empreintes-livrees.txt}"
PROPRIO="${PROPRIO:-}"

empreinte() { sha256sum < "$1" | cut -d' ' -f1; }

poser() {   # poser <source> <destination> : copie atomique (temporaire dans le même dossier puis renommage)
  local tmp
  tmp=$(mktemp "${CIBLE}/.reference.XXXXXX")
  if cp -- "$1" "$tmp" && chmod 0644 "$tmp" && { [[ -z "$PROPRIO" ]] || chown "$PROPRIO" "$tmp"; } \
     && mv -f -- "$tmp" "$2"; then
    return 0
  fi
  rm -f -- "$tmp"
  echo "secubox-profiles : écriture de $2 impossible" >&2
  return 1
}

[[ -d "$CIBLE" ]] || { echo "secubox-profiles : ${CIBLE} absent, rien à mettre à jour" >&2; exit 0; }

for ref in "$SOURCE"/*.toml; do
  [[ -f "$ref" ]] || continue
  nom=$(basename -- "$ref")
  dest="${CIBLE}/${nom}"
  if [[ -L "$dest" ]]; then
    echo "secubox-profiles : ${dest} est un lien, non touché" >&2
    continue
  fi
  if [[ ! -e "$dest" ]]; then
    poser "$ref" "$dest"
    echo "secubox-profiles : profil ${nom} installé" >&2
    continue
  fi
  neuf=$(empreinte "$ref")
  local_=$(empreinte "$dest")
  [[ "$neuf" == "$local_" ]] && continue
  if [[ -f "$EMPREINTES" ]] && grep -qxF -- "${local_}  ${nom}" "$EMPREINTES"; then
    poser "$ref" "$dest"
    rm -f -- "${dest}.dpkg-dist"
    echo "secubox-profiles : profil ${nom} mis à jour (copie non modifiée d'une version livrée)" >&2
  else
    poser "$ref" "${dest}.dpkg-dist"
    echo "secubox-profiles : ${nom} modifié localement, gardé ; nouvelle référence : ${dest}.dpkg-dist" >&2
  fi
done
exit 0
