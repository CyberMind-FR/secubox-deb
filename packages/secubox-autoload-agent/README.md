<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-autoload-agent

Provisionnement réseau « Auto-Load », **côté box cliente**. Parent #2182, cadrage `docs/dossiers/provisionnement-auto-load.md`. Le côté infrastructure est `secubox-autoload`.

**État (0.1.0, #2189) :** le tunnel sortant. Le moteur de provisioning (#2187), la validation (#2188) et le rapport (#2192) viennent ensuite.

## Tunnel (`autoload_agent/tunnel.py`)

- La clé WireGuard est générée **sur la box** (`/etc/secubox/secrets/autoload-wg.key`, 0600). Jamais dans l'image, jamais en argument de commande ni dans la configuration (`PostUp = wg set %i private-key <fichier>`). Une clé existante n'est **jamais** remplacée : la box garde son identité.
- Configuration **sortante seulement** : pas de `ListenPort`, pas de route par défaut (`AllowedIPs` = le hub `10.64.0.1/32`), `PersistentKeepalive = 25`. Aucun port entrant côté client.
- Ce que répond l'infrastructure est **validé avant d'écrire un fichier** : nom d'hôte épinglé (`admin.gk2.secubox.in`), adresse /32 dans `10.64.0.0/16` hors hub, clés WireGuard, aucun retour à la ligne, aucun champ inconnu.
- Si l'activation de `wg-quick@wg-autoload` échoue, la configuration posée est retirée.

## Tests

    python3 -m pytest packages/secubox-autoload-agent/tests
