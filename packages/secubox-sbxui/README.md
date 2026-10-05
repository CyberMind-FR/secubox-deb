<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-sbxui

SecuBox WebOS — bibliothèque UI partagée (objets sbx).

Bibliothèque partagée du design system SBXOS (le WebOS/Hall) : le slicer de pied (SBXSliceBar), l'aide reverse-design (SBXAide), et les skins associés (slicebar.css, spicy.css). Elle est servie sous /shared/sbxui/ sur chaque vhost de module (via l'alias /shared/), pour que tout module — Hall ou service à origine distincte (ex. secubox-radio) — partage EXACTEMENT le même chrome et la même aide contextuelle. Source de vérité unique : cf. HIG.md du WebOS et scripts/sync-sbxui.sh (qui aligne la copie locale du Hall).

Paquet Debian : version `0.1.2-1~bookworm1`, architecture `all`.

## Contenu

- `www/` : interface web
