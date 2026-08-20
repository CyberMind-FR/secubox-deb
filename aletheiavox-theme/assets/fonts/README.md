<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# Polices AletheiaVox — à déposer ici

`css/typography.css` déclare trois `@font-face` qui pointent vers CE dossier :

| Fichier attendu       | Famille          | Usage                       |
|-----------------------|------------------|-----------------------------|
| `cinzel.woff2`        | Cinzel           | Titres (`.av-display`)      |
| `inter.woff2`         | Inter            | Interface & lecture (corps) |
| `jetbrainsmono.woff2` | JetBrains Mono   | Données, logs, mono         |

## Pourquoi auto-héberger

La politique de sécurité de contenu des applications SecuBox (`default-src 'self'`)
**interdit les polices externes** : pas de Google Fonts en production. Chaque
fonte est une variable — un seul `.woff2` couvre toute la plage de graisses —
et `font-display:swap` affiche la pile système en attendant, sans bloquer le
rendu.

## D'où les copier

Les trois fichiers **existent déjà** dans le dépôt, servis par le BBS :

```
packages/secubox-bbs/internal/web/static/fonts/cinzel.woff2
packages/secubox-bbs/internal/web/static/fonts/inter.woff2
packages/secubox-bbs/internal/web/static/fonts/jetbrainsmono.woff2
```

Copie directe :

```bash
cp packages/secubox-bbs/internal/web/static/fonts/*.woff2 \
   aletheiavox-theme/assets/fonts/
```

> Ce sont des binaires : ils ne sont pas dupliqués dans ce dossier de gabarit
> pour ne pas alourdir le dépôt. Référence unique = le dossier du BBS ci-dessus.
> Si vous servez le thème sous un autre chemin, ajustez les `url(...)` de
> `css/typography.css` en conséquence.
