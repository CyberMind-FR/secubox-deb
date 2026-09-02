#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# ══════════════════════════════════════════════════════════════════════════════
#  scripts/sync-issues.sh — backlog GitHub ⇆ fichiers de suivi (.claude/*)
#
#  PRINCIPE : les fichiers de suivi sont la source de vérité de ce qui est FAIT.
#  Une résolution est enregistrée par un marqueur MACHINE-LISIBLE, jamais par du
#  texte libre (car HISTORY journalise AUSSI des issues « filed for later » /
#  « ouvertes », qu'il ne faut PAS fermer). Marqueurs reconnus, insensibles à la
#  casse :
#       closes #N   |   fixes #N   |   FERMÉ #N   |   RÉSOLU #N
#  Écris-les uniquement quand c'est terminé ET déployé.
#
#  Le script relève ces marqueurs dans .claude/HISTORY.md et .claude/WIP.md, et
#  pour chaque #N ENCORE OUVERTE sur GitHub, la ferme (avec un commentaire). Les
#  issues non marquées restent ouvertes (backlog / non touchées).
#
#  Usage :
#    scripts/sync-issues.sh --dry-run     # montre ce qui serait fermé (défaut)
#    scripts/sync-issues.sh --apply       # ferme réellement
#
#  Réseau : utilise `gh` (HTTPS). Si la route directe vers GitHub est coupée,
#  exporter un proxy avant de lancer, p.ex. via le Tor de la box :
#    export HTTPS_PROXY=socks5://192.168.1.200:9050 ALL_PROXY=socks5://192.168.1.200:9050
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
FILES=("$REPO/.claude/HISTORY.md" "$REPO/.claude/WIP.md")
MODE="dry-run"

for a in "$@"; do
  case "$a" in
    --apply)   MODE="apply" ;;
    --dry-run) MODE="dry-run" ;;
    -h|--help) sed -n '9,33p' "$0"; exit 0 ;;
    *) echo "arg inconnu: $a" >&2; exit 2 ;;
  esac
done

command -v gh >/dev/null || { echo "gh introuvable" >&2; exit 2; }
gh auth status >/dev/null 2>&1 || { echo "gh non authentifié (gh auth login)" >&2; exit 2; }

# Marqueur de résolution → numéros d'issue.
MARKER='(closes?|closed|fixe[sd]?|fixes|résolu[e]?|résout|ferm[ée]e?|FERM[ÉE]|R[ÉE]SOLU)[[:space:]:]*#[0-9]{2,5}'
mapfile -t NUMS < <(grep -hoiE "$MARKER" "${FILES[@]}" 2>/dev/null \
  | grep -oE '#[0-9]{2,5}' | tr -d '#' | sort -un)

[ "${#NUMS[@]}" -gt 0 ] || { echo "Aucun marqueur closes/FERMÉ/RÉSOLU trouvé dans les fichiers de suivi."; exit 0; }

echo "Marqueurs de résolution trouvés : ${NUMS[*]}"
echo "Mode : $MODE"; echo

closed=0; kept=0
for n in "${NUMS[@]}"; do
  state="$(gh issue view "$n" --json state --jq .state 2>/dev/null || echo MISSING)"
  case "$state" in
    OPEN)
      if [ "$MODE" = "apply" ]; then
        gh issue close "$n" \
          --comment "Fermeture automatique (scripts/sync-issues.sh) : marquée résolue dans .claude/ (closes/FERMÉ/RÉSOLU). Rouvrir si ce n'est pas le cas." \
          >/dev/null && echo "  fermée  #$n"
      else
        echo "  À FERMER #$n (ouverte)"
      fi
      closed=$((closed+1)) ;;
    CLOSED)  kept=$((kept+1));            echo "  déjà fermée #$n" ;;
    MISSING) echo "  introuvable #$n (ignorée)" ;;
  esac
done

echo
echo "Résumé : $closed à fermer/fermées, $kept déjà fermées."
[ "$MODE" = "dry-run" ] && echo "(dry-run — relancer avec --apply pour fermer)"
