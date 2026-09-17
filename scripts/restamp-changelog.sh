#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: restamp-changelog
#
# Retamponne l'entree de TETE d'un debian/changelog pour une suite cible.
#
# POURQUOI PLUTOT QUE 168 FICHIERS. Le suffixe `~bookworm1` et le champ
# distribution existent pour separer les suites dans l'archive apt. Les porter
# a la main voudrait dire une entree de changelog par paquet et par suite :
# 168 fichiers a editer, a re-editer a chaque release, et deux sources de
# verite a garder synchrones — elles divergeront. Le suffixe est une propriete
# de la CONSTRUCTION, pas du code : on le pose au moment de construire.
#
# L'arbre de travail de la CI est ephemere ; rien n'est ecrit dans le depot.
#
# Usage : restamp-changelog.sh <suite> [chemin/vers/changelog]
#         restamp-changelog.sh trixie packages/secubox-core/debian/changelog
#         restamp-changelog.sh --verifier <suite>   (essai a blanc sur tout)

set -uo pipefail
readonly MODULE="restamp-changelog"
readonly VERSION="1.0.0"

# La ligne de tete : NOM (VERSION) DISTRIBUTION; urgency=...
#   secubox-core (1.5.5-1~bookworm1) bookworm; urgency=medium
retamponner() {
    local suite="$1" ligne="$2"
    [[ "$ligne" =~ ^([^[:space:]]+)[[:space:]]+\(([^\)]+)\)[[:space:]]+([^\;]+)\;(.*)$ ]] || {
        echo "  ligne de tete non reconnue : $ligne" >&2; return 1; }
    local nom="${BASH_REMATCH[1]}" ver="${BASH_REMATCH[2]}" reste="${BASH_REMATCH[4]}"

    # Un suffixe ~<suite><n> deja present est REMPLACE ; sinon on en ajoute un.
    # Les cinq paquets a revision nue (1.2.0-1) en recoivent donc un aussi :
    # sans lui, la construction trixie porterait un numero IDENTIQUE a la
    # bookworm et apt ne saurait plus les distinguer.
    if [[ "$ver" =~ ^(.*)~[a-z]+([0-9]+)$ ]]; then
        ver="${BASH_REMATCH[1]}~${suite}${BASH_REMATCH[2]}"
    else
        ver="${ver}~${suite}1"
    fi
    printf '%s (%s) %s;%s\n' "$nom" "$ver" "$suite" "$reste"
}

# ── Mode verification : essai a blanc sur tous les changelogs du depot
if [[ "${1:-}" == "--verifier" ]]; then
    suite="${2:?suite attendue}"
    n=0; ko=0
    for f in packages/*/debian/changelog; do
        tete=$(head -1 "$f")
        if sortie=$(retamponner "$suite" "$tete"); then
            n=$((n+1))
            [[ "$sortie" == *"~${suite}"* && "$sortie" == *") ${suite};"* ]] || {
                echo "  INATTENDU : $f"; echo "    $tete"; echo "    -> $sortie"; ko=$((ko+1)); }
        else
            echo "  ECHEC : $f"; ko=$((ko+1))
        fi
    done
    echo "  $n changelog(s) retamponnables, $ko probleme(s)"
    [[ $ko -eq 0 ]]
    exit $?
fi

suite="${1:?usage: restamp-changelog.sh <suite> [changelog]}"
fichier="${2:-debian/changelog}"
[[ -f "$fichier" ]] || { echo "[$MODULE] absent : $fichier" >&2; exit 1; }

tete=$(head -1 "$fichier")
neuf=$(retamponner "$suite" "$tete") || exit 1
if [[ "$tete" == "$neuf" ]]; then
    echo "[$MODULE] deja en $suite : $tete"
    exit 0
fi
printf '%s\n' "$neuf" > "${fichier}.tmp"
tail -n +2 "$fichier" >> "${fichier}.tmp"
mv "${fichier}.tmp" "$fichier"
echo "[$MODULE] $tete"
echo "[$MODULE]   -> $neuf"
