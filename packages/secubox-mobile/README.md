<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
-->

# secubox-mobile

Méta-paquet du profil **mobile** : clé USB amd64, agent sur un réseau existant, sans mode routeur ni Hall.
Il reprend `secubox-minimal` ; `packages/secubox-profiles/profiles/mobile.toml` y ajoute le kiosque et la console.

Le réseau reçoit la box comme **seul** DNS. Si la clé est arrachée, l'utilisateur rétablit le DNS à la main.
