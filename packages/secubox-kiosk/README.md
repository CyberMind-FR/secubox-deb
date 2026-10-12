<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-kiosk

Outil d'installation et de réglage du kiosque graphique (Chromium plein écran sur la WebUI SecuBox).

```
apt-get install secubox-kiosk
secubox-kiosk-setup install --x11     # paquets graphiques + utilisateur secubox-kiosk
secubox-kiosk-setup enable --x11      # démarrage automatique ; redémarrer ensuite
secubox-kiosk-setup status
secubox-kiosk-setup disable           # retour à la console
```

`--wayland` (Cage, exige le DRM) est l'alternative au mode X11, recommandé par défaut.
Le lanceur `/usr/sbin/secubox-kiosk-launcher` que l'unité générée appelle vient de `secubox-premier-pas`.
