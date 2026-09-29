#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: construire-front — construit le front d'un paquet (#1611).
# UN SEUL producteur pour la CI et pour le poste qui alimente apt.secubox.in
# (#1335) : Node épinglé par .nvmrc, npm ci strict, types, build, art,
# budgets, balayage, puis dist/.construit qui lie le dist à ses sources.
# debian/rules ne lance jamais npm : il VÉRIFIE ce fichier.
set -euo pipefail
readonly MODULE="construire-front"
ICI="$(cd "$(dirname "$0")" && pwd)"
PAQ="${1:?usage : construire-front.sh packages/<paquet>}"
cd "$PAQ"

voulu="$(cat .nvmrc)"; eu="$(node -p 'process.versions.node.split(".")[0]')"
[ "$eu" = "$voulu" ] || { echo "$MODULE : Node $eu, .nvmrc exige $voulu" >&2; exit 1; }

npm ci --no-audit --no-fund
npm audit signatures >/dev/null 2>&1 || echo "$MODULE : audit signatures indisponible (avertissement)" >&2
npm run -s types
npm run -s test
npm run -s build
npm run -s art

# Budgets (#1616) : l'app (aiguillage + racine) ≤ 190 Ko gzip ; la carte
# légère que le Hall charge à chaque visite (aiguillage + carte + ses
# dépendances, sans React) ≤ 15 Ko gzip.
gz() { local n=0; for f in "$@"; do [ -f "$f" ] && n=$((n + $(gzip -9c "$f" | wc -c))); done; echo "$n"; }
aig=$(ls dist/assets/aurora-*.js | head -1)
taille=$(gz "$aig" dist/assets/racine-*.js)
[ "$taille" -le 194560 ] || { echo "$MODULE : app $taille o gzip > 190 Ko" >&2; exit 1; }
if ls dist/assets/carte-*.js >/dev/null 2>&1; then
  carte=$(gz "$aig" dist/assets/carte-*.js dist/assets/enfant-*.js)
  if grep -lq "react" dist/assets/carte-*.js; then echo "$MODULE : la carte légère importe React" >&2; exit 1; fi
  [ "$carte" -le 15360 ] || { echo "$MODULE : carte légère $carte o gzip > 15 Ko" >&2; exit 1; }
fi

# Balayage : aucune autre origine, aucun eval, aucun chemin manuel.
if grep -lE "https?://" dist/aurora/index.html dist/assets/*.css 2>/dev/null | grep -q .; then
  echo "$MODULE : origine externe dans le dist (html/css)" >&2; exit 1; fi
if grep -rlE "\beval\(|new Function\(|/acces/[a-z]+/manuel" dist/assets 2>/dev/null | grep -q .; then
  echo "$MODULE : construction interdite (eval / new Function / /manuel)" >&2; exit 1; fi

# Jumeaux .gz pour gzip_static (jamais index.html : le drapeau LAN y est injecté).
find dist/assets -type f \( -name '*.js' -o -name '*.css' -o -name '*.json' \) -exec gzip -9kf {} \;

amont="$(dpkg-parsechangelog -l debian/changelog -SVersion | sed -E 's/-[^-]+$//; s/~(bookworm|trixie)[0-9]*$//')"
canal=publie; case "$amont" in *~aurora*) canal=apercu ;; esac
empreinte="$(bash "$ICI/empreinte-front.sh" .)"
printf '{"version":"%s","canal":"%s","empreinte":"%s"}\n' "$amont" "$canal" "$empreinte" > dist/.construit
printf '{"version":"%s","canal":"%s"}\n' "$amont" "$canal" > dist/aurora/version.json
echo "$MODULE : $amont ($canal) ; app $taille o gzip ; carte ${carte:-?} o gzip ; empreinte ${empreinte:0:12}"
