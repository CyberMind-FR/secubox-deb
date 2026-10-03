#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
#
# SecuBox-Deb :: tests-par-paquet.sh (ref #1294) — lance la suite pytest de CHAQUE paquet, un dossier à la fois, et résume.
#
# Pourquoi un script : une suite par paquet (pytest.ini propres, chemins relatifs) — un seul `pytest` à la racine ne marche pas.
# Sert surtout à COMPARER deux environnements (ex. le .venv du dépôt et un chroot Debian 13 / Python 3.13) : ce qui échoue
# dans les deux est ancien ; ce qui n'échoue que dans le second est ce que la migration casse.
#
# Usage : scripts/tests-par-paquet.sh [--python CMD] [--sortie FICHIER.tsv] [--delai S] [paquet ...]
#   --python  interpréteur (défaut : python3)         --delai  secondes par paquet (défaut 300)
# Sortie TSV : paquet <TAB> code <TAB> réussis <TAB> échoués <TAB> erreurs <TAB> ignorés <TAB> durée_s
set -uo pipefail
RACINE="$(cd "$(dirname "$0")/.." && pwd)"
PY="python3"; SORTIE="/dev/stdout"; DELAI=300; PAQUETS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --python) PY="$2"; shift 2 ;;
    --sortie) SORTIE="$2"; shift 2 ;;
    --delai)  DELAI="$2"; shift 2 ;;
    *)        PAQUETS+=("$1"); shift ;;
  esac
done
if [ "${#PAQUETS[@]}" -eq 0 ]; then
  for d in "$RACINE"/packages/*/tests; do [ -d "$d" ] && PAQUETS+=("$(basename "$(dirname "$d")")"); done
fi
: > "$SORTIE"
export PYTHONDONTWRITEBYTECODE=1
for p in "${PAQUETS[@]}"; do
  dir="$RACINE/packages/$p"
  [ -d "$dir/tests" ] || continue
  deb=$(date +%s)
  sortie=$(cd "$dir" && timeout "$DELAI" $PY -m pytest tests -q -p no:cacheprovider 2>&1); code=$?
  fin=$(date +%s)
  res=$(printf '%s\n' "$sortie" | grep -E "[0-9]+ (passed|failed|error|skipped|deselected)" | tail -1)
  n() { printf '%s' "$res" | grep -oE "[0-9]+ $1" | head -1 | grep -oE "[0-9]+" || echo 0; }
  [ "$code" = 124 ] && res="delai"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$p" "$code" "$(n passed)" "$(n failed)" "$(n error)" "$(n skipped)" "$((fin-deb))" >> "$SORTIE"
done
