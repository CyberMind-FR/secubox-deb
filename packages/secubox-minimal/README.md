<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-minimal

Méta-paquet du profil **minimal**, pour une petite carte (ESPRESSObin, 1 Go).

## Contenu

DPI (`secubox-dpi`, `secubox-ndpid-engine` >= 1.7.2), garde DNS, filtre de publicités, NAC, Freebox, garde IPv6, filtrage web, WireGuard (`secubox-wireguard` >= 1.3.0, sortie
Internet pour clients distants), agent Auto-Load, et le seul socle d'administration (core, aggregator, system, hardening, hub, portal, auth).

## Exclusions (`Conflicts`)

`secubox-webos` (Hall), `secubox-waf-ng` et `secubox-waf` (le WAF reste sur l'infrastructure), `secubox-metrics`. Un `Recommends` de `secubox-auth` ou de `secubox-freebox` ramenait le
Hall : le `Conflicts` est le seul moyen de dire à apt de ne pas le reprendre. `secubox-portal` est gardé : il livre `login.html`, la page de connexion de la WebUI.

## Profil d'activation

`packages/secubox-profiles/profiles/minimal.toml` : ce que `secubox-profilectl apply --profile minimal` laisse allumé. Il doit rester le miroir de ce méta-paquet.

## Historique d'essai

0.4.0 avait ajouté HAProxy et le WAF : sur 951 Mo, la carte a saturé (swap plein, charge > 10, deux coupures franches). Retirés en 0.5.0 (#2849). Voir `docs/FAQ-ESPRESSOBIN-1GO.md`.

## Tests

`pytest packages/secubox-minimal/tests` : fermeture des dépendances (aucun module exclu, même indirect), `Conflicts`, version minimale de `ndpid-engine`.
