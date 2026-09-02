#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: sync-sbxui
# La bibliothèque UI partagée (objets sbx) a UNE source de vérité :
#   packages/secubox-sbxui/www/{aide.js,slicebar.js,slicebar.css,spicy.css}
# Le Hall (secubox-webos) en sert une COPIE locale sous /cardlets/../ (même
# origine, includes relatifs). Ce script réaligne cette copie sur la source, et
# en mode --check échoue si elles ont dérivé (à câbler en CI). Voir HIG §6.
set -euo pipefail

ici="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src="$ici/packages/secubox-sbxui/www"
dst="$ici/packages/secubox-webos/www/hall"
fichiers=(aide.js slicebar.js slicebar.css spicy.css)

mode="${1:-sync}"
drift=0
for f in "${fichiers[@]}"; do
  if [[ ! -f "$src/$f" ]]; then echo "manquant (source) : $src/$f" >&2; exit 2; fi
  if [[ "$mode" == "--check" ]]; then
    if ! cmp -s "$src/$f" "$dst/$f"; then
      echo "DÉRIVE : $dst/$f diffère de la source secubox-sbxui" >&2
      drift=1
    fi
  else
    cp "$src/$f" "$dst/$f"
    echo "sync : $f → secubox-webos/www/hall/"
  fi
done

if [[ "$mode" == "--check" ]]; then
  [[ "$drift" -eq 0 ]] && echo "sbxui : Hall aligné sur la source ✓" || { echo "→ lancer scripts/sync-sbxui.sh pour réaligner" >&2; exit 1; }
fi
