<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Posters VILLAGE3B — assets

Référence pour le poster public grand format basé sur le brief
`docs/marketing/POSTER-grand-public-village3b.md`.

## Fichiers attendus dans ce dossier

- `village3b-A2.png` — poster A2 portrait haute résolution (300dpi, ~5MB)
- `village3b-A2.svg` — source vectoriel Inkscape éditable
- `village3b-A4.pdf` — variante A4 print-ready
- `village3b-social-1080x1080.png` — variante Instagram/LinkedIn
- `village3b-story-1080x1920.png` — variante Story Instagram/Snapchat

## Brief layout (6 zones)

Voir `docs/marketing/POSTER-grand-public-village3b.md` pour le détail des
6 zones (titre, niveaux R0/R1/R2, 9 widgets metrics, transparence,
conformité, QR codes, footer).

## QR codes embedded

Le poster contient 3 QR codes pointant vers les endpoints FastAPI :
- ① SPLASH      → `http://village3b/`
- ② CERT iPHONE → `http://village3b/ca/mobileconfig`
- ③ WEBCLIP HOME → `http://village3b/ca/webclip-cabine.mobileconfig`

Les URLs sont auto-générées par les routes `/qr/{splash,cert,webclip}.png`
de l'API (Phase 3.x #497 + #495).

## Charte couleurs

```
--cosmos-black: #0a0a0f          /* fond */
--gold-hermetic: #c9a84c         /* accents titre */
--matrix-green: #00ff41          /* texte principal */
--phos: #00dd44                  /* bordures P31 */
--phos-hot: #00ff55              /* highlights */
--amber: #ffb347                 /* warning R2 */
--cinnabar: #e63946              /* alertes risque HIGH */
```

## Print specs

- A2 portrait, 420×594 mm, marges 15mm, 3mm bleed
- 300dpi minimum
- CMYK pour print, RGB pour digital
- Papier mat 200g/m² recommandé

## Licence

LicenseRef-CMSD-1.0 — image dérivée du logiciel cabine ToolBox.

## Issue tracking

[#497 — Poster grand public VILLAGE3B](https://github.com/CyberMind-FR/secubox-deb/issues/497)
