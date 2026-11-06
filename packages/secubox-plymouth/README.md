<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-->
# secubox-plymouth

Démarrage graphique des plateformes avec écran : le dé du logo du Hall en rotation, et une barre Aurora.

- 90 images dans `theme/secubox-dice/`, rendues par `outils/rendre-de.py` depuis `sbx-dice.js`.
- Le kiosque arrête Plymouth (`ExecStartPre`). Sans kiosque, arrêt standard.
- Aucune API, aucun port, aucune configuration. Le thème entre dans l'initramfs au prochain `update-initramfs`.
- Sur RPi, ne jamais lancer `update-initramfs` sans ROOTPART : passer par `secubox-rpi-dsi update-initramfs`.
