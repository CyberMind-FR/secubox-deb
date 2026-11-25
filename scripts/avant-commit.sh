#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: avant-commit (#3950) — rejoue en local les contrôles de CI qui échouent le plus, seulement ceux que les fichiers
# modifiés depuis origin/master (ou la base donnée) concernent. Lecture seule. Usage : scripts/avant-commit.sh [base]
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
base="${1:-origin/master}"
mapfile -t F < <({ git diff --name-only "$(git merge-base "$base" HEAD)"; git ls-files --others --exclude-standard; } | sort -u)
[[ ${#F[@]} -gt 0 ]] || { echo "avant-commit : rien de modifié depuis $base"; exit 0; }
PY=python3; for c in .venv/bin/python "$(git rev-parse --git-common-dir)/../.venv/bin/python"; do [[ -x $c ]] && PY=$c && break; done
rc=0
touche() { printf '%s\n' "${F[@]}" | grep -qE "$1"; }
passe() { local nom="$1"; shift; if "$@" >/tmp/avant-commit.$$ 2>&1; then echo "ok   $nom"; else echo "ÉCHEC $nom"; tail -15 /tmp/avant-commit.$$; rc=1; fi; rm -f /tmp/avant-commit.$$; }

passe "licence (en-têtes CMSD-1.0)" python3 scripts/license-headers.py --check
if touche '^packages/[^/]+/(menu\.d/|debian/control)|espaces\.json'; then
  passe "menu et espaces du hub" "$PY" -m pytest -q packages/secubox-hub/tests/test_espaces_2212.py packages/secubox-hub/tests/test_menu_categories.py
fi
if touche '^packages/[^/]+/debian/control|arbre\.yaml'; then
  passe "catalogue des métapaquets" "$PY" -m pytest -q packages/secubox-appstore/tests/test_catalogue_groupes_2050.py
fi
if touche 'apparmor|secubox-.*apparmor'; then
  passe "droits réels (audit.log)" "$PY" -m pytest -q packages/secubox-pilotage/tests/test_droits_reels_3126.py
fi
while read -r pkg; do
  [[ -d packages/$pkg/tests ]] && passe "tests $pkg" "$PY" -m pytest -q "packages/$pkg/tests"
done < <(printf '%s\n' "${F[@]}" | sed -nE 's#^packages/([^/]+)/.*#\1#p' | sort -u)
if git log --format=%B "$(git merge-base "$base" HEAD)..HEAD" | grep -niE '\b(close[sd]?|fix(es|ed)?|resolve[sd]?) #[0-9]+'; then
  echo "ÉCHEC message : un commit ou une PR ne ferme pas une issue avant déploiement (AGENTS.md) — écrire (ref #N)"; rc=1
fi
exit $rc
