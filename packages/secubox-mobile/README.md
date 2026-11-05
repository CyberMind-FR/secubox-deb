<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-->

# secubox-mobile

Méta-paquet du profil **mobile** : clé USB amd64, agent sur un réseau existant, sans mode routeur ni Hall.
Il reprend `secubox-minimal` ; `packages/secubox-profiles/profiles/mobile.toml` y ajoute le kiosque et la console.

Le réseau reçoit la box comme **seul** DNS, en IPv4 et en IPv6. Si la clé est arrachée, l'utilisateur rétablit le DNS à la main.

## API (socket `/run/secubox/mobile.sock`)

- `GET /api/v1/mobile/etat` (`require_lecture`) : adresse, listes, Freebox, IPv6.
- `POST /api/v1/mobile/retirer`, `POST /api/v1/mobile/reactiver` (`require_jwt`).

Page : `/mobile/`. Contrôleur root : `secubox-mobilectl activer|retirer [--manuel]|reactiver|etat`, état dans
`/var/lib/secubox-mobile/etat.json` (root, 0700).

Garanties : la Freebox ne vise la clé que si son DNS répond ; l'origine est synchronisée avant tout changement ; un
réglage changé par l'utilisateur n'est ni réécrit ni écrasé ; sur une autre Freebox, rien n'est touché.
