#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: check-merge-overwrite (#1748)
#
# Détecte les fusions qui ÉCRASENT le travail de master : un fichier .py modifié des DEUX
# côtés depuis la base commune, dont la fusion reprend le blob d'UN côté, octet pour octet
# (une vraie fusion à trois voies ne le produit pas : c'est une résolution « prendre le
# leur », ou une branche ancienne réimposée). Cas réel : aff481735 (2026-08-17) a remis
# l'api/main.py de 12 paquets à leur version de juin.
#
# Usage :
#   check-merge-overwrite.sh [--since AAAA-MM-JJ] [--ref <ref>]   historique (défaut : depuis 2026-06-01, HEAD)
#   check-merge-overwrite.sh --commit <fusion>                    une seule fusion
#   check-merge-overwrite.sh --range <A>..<B>                     les fusions de A..B (CI : celles d'une PR)
# Sortie : une ligne « <court> <date> <fichier> » par écrasement. Code 1 s'il y en a, 0 sinon.
set -euo pipefail

since="2026-06-01"
ref="HEAD"
mode="histoire"
cible=""
while [ $# -gt 0 ]; do
  case "$1" in
    --since)  since="$2"; shift 2 ;;
    --ref)    ref="$2"; shift 2 ;;
    --commit) mode="commit"; cible="$2"; shift 2 ;;
    --range)  mode="plage"; cible="$2"; shift 2 ;;
    *) echo "usage: $0 [--since AAAA-MM-JJ] [--ref <ref>] | --commit <fusion> | --range A..B" >&2; exit 2 ;;
  esac
done

found=0

verifie() {   # $1 = commit de fusion
  local M="$1" P1 P2 B f b m p1 p2
  local -a P
  read -r -a P <<<"$(git rev-list --parents -n1 "$M")"
  [ "${#P[@]}" -eq 3 ] || return 0            # fusions à deux parents seulement
  P1=${P[1]}; P2=${P[2]}
  B=$(git merge-base "$P1" "$P2") || return 0
  while IFS= read -r f; do
    b=$(git rev-parse -q --verify "$B:$f")  || continue
    m=$(git rev-parse -q --verify "$M:$f")  || continue
    p1=$(git rev-parse -q --verify "$P1:$f") || continue
    p2=$(git rev-parse -q --verify "$P2:$f") || continue
    # modifié des deux côtés, et la fusion = le côté P2 exactement
    if [ "$p1" != "$b" ] && [ "$p2" != "$b" ] && [ "$m" = "$p2" ] && [ "$p1" != "$p2" ]; then
      echo "$(git log -1 --format='%h %ad' --date=short "$M") $f"
      found=1
    fi
  done < <(git diff --name-only "$P1" "$M" -- '*.py')
}

case "$mode" in
  commit)   verifie "$cible" ;;
  plage)    for M in $(git rev-list --merges "$cible"); do verifie "$M"; done ;;
  histoire) for M in $(git rev-list --merges --since="$since" "$ref"); do verifie "$M"; done ;;
esac
exit "$found"
