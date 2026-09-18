#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: publication APT LOCALE, sur la machine qui heberge le depot.
#
# POURQUOI UNE VERSION LOCALE (#1294). La publication passait par la CI, qui
# executait apt-publish-remote.sh sur la board via ssh. Cette voie est MORTE :
# le depot GitHub ne porte AUCUN secret — ni GPG_PRIVATE_KEY, ni DEPLOY_SSH_KEY
# — alors que trois sont declares `required: true`. Le job `Publish Packages`
# se contentait d'etre `skipped`, ce qui se lit « rien a faire » et non « je ne
# peux pas » : l'index publie est ainsi reste fige au 24 aout pendant que la
# base reprepro, elle, avancait. Un mois durant, les clients ont recu des
# versions obsoletes sans qu'aucun voyant ne passe au rouge.
#
# Ce script fait le meme travail, depuis la machine elle-meme.
#
# CE N'EST PAS UN rsync DU DEPOT. reprepro possede sa base de donnees ; un
# `rsync --delete` l'ecraserait sans la connaitre. On depose dans la zone de
# transit et on laisse reprepro travailler, exactement comme a la main.
#
# PAS `processincoming` non plus : il attend des `.changes`, que la chaine de
# construction ne produit pas (paquets batis avec `-b`, non signes).
#
# Usage :
#   secubox-apt-publish                 # suite deduite de chaque paquet
#   secubox-apt-publish --dist trixie   # tout dans une suite imposee
#   secubox-apt-publish --essai         # montre sans importer

set -euo pipefail
readonly MODULE="apt-publish-local"
readonly VERSION="1.0.0"

BASE="${APT_BASE:-/data/apt}"
DIST=""          # vide = deduite du suffixe de version de chaque paquet
ESSAI=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dist)   DIST="$2"; shift 2 ;;
    --essai|--dry-run) ESSAI=1; shift ;;
    -h|--help) sed -n '1,40p' "$0" | grep '^#' | sed 's/^# \?//'; exit 0 ;;
    *) echo "option inconnue : $1" >&2; exit 2 ;;
  esac
done

command -v reprepro >/dev/null || { echo "[$MODULE] reprepro absent" >&2; exit 1; }
[ -d "$BASE/conf" ] || { echo "[$MODULE] $BASE n'est pas un depot reprepro" >&2; exit 1; }

# Les suites REELLEMENT declarees, pour ne pas inventer une cible.
mapfile -t SUITES < <(awk '/^Codename:/{print $2}' "$BASE/conf/distributions")

# DEDUIRE LA SUITE DU PAQUET. Le suffixe `~<suite><n>` est pose a la
# construction (cf. scripts/restamp-changelog.sh) : il dit pour quelle suite le
# paquet a ete bati. S'y fier evite de ranger un `~trixie1` dans bookworm sur
# une simple erreur de frappe — ce qui passerait inapercu jusqu'a ce qu'un
# client l'installe.
suite_du_paquet() {
  local nom="$1" s
  for s in "${SUITES[@]}"; do
    [[ "$nom" == *"~${s}"* ]] && { echo "$s"; return 0; }
  done
  return 1
}

shopt -s nullglob
declare -A comptes
ok=0; refuses=(); ignores=()

for deb in "$BASE"/incoming/*.deb; do
  nom="$(basename "$deb")"
  if [[ -n "$DIST" ]]; then
    cible="$DIST"
  elif ! cible="$(suite_du_paquet "$nom")"; then
    ignores+=("$nom"); continue
  fi

  if [[ $ESSAI -eq 1 ]]; then
    echo "  [essai] $nom -> $cible"; comptes[$cible]=$(( ${comptes[$cible]:-0} + 1 )); ok=$((ok+1)); continue
  fi

  if reprepro -b "$BASE" includedeb "$cible" "$deb" >/dev/null 2>&1; then
    ok=$((ok+1)); comptes[$cible]=$(( ${comptes[$cible]:-0} + 1 ))
    rm -f "$deb"
  else
    # UN REFUS ISOLE EST LE CAS ORDINAIRE : reimporter une version deja
    # presente. On le nomme, on le GARDE en transit pour inspection, on
    # continue.
    refuses+=("$nom")
  fi
done

echo "[$MODULE] importes: $ok — refuses: ${#refuses[@]} — ignores: ${#ignores[@]}"
for s in "${!comptes[@]}"; do echo "  $s : ${comptes[$s]}"; done
for r in "${refuses[@]}";  do echo "  refuse : $r"; done
for i in "${ignores[@]}";  do echo "  ignore (suite indeterminee) : $i"; done

# ZERO IMPORT EST UNE ERREUR, PAS UN SILENCE. C'est le seul signal qui dit que
# la publication n'a rien produit — sans quoi on rendrait « vert » sur un depot
# inchange, precisement le defaut que ce script corrige.
if [[ $ok -eq 0 ]]; then
  echo "[$MODULE] aucun paquet importe — la publication n'a rien change" >&2
  exit 1
fi
