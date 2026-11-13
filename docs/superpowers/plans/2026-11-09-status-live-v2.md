<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# SecuBox Status Live v2 — plan (#3595)

Spécification : `docs/superpowers/specs/2026-11-09-status-live-v2.md`.

## Jalons

| Jalon | Contenu | Livrable |
|---|---|---|
| 0 · Audit | chemins réels gk2/gk3/c3box, unités, clés Annuaire, profils de déploiement, contrat JSON v2, arbitrage des questions §11 | spec validée |
| 1 · Moteur local | paquet, collecteurs health/modules/profiles/système, normalisation, SQLite WAL, fraîcheur, tests | premier relevé local fiable sur gk2 |
| 2 · Fédération | `StatusSnapshot`, signature Ed25519, publication Annuaire, vérification DID, anti-rejeu, nœuds absents | flotte avec relevés vérifiés |
| 3 · API et interface | API publique et privée, WebUI, historique 24 h / 7 j / 30 j, incidents, vue par appliance, exposition HAProxy + WAF | `status.gk2.secubox.in` sur données réelles |
| 4 · Production | tests de panne, signature, charge, restauration ; arm64 et amd64 ; installation des trois nœuds ; doc et publication apt | Status Live v2 en production |

## Ordre de déploiement

1. gk2 : collecte locale et API.
2. gk3 : premier pair fédéré (**sur accord explicite**, gk3 = voicestudio).
3. c3box : troisième nœud.
4. gk2 : vue consolidée et publication publique.

Les capacités de gk3 et c3box viennent de leur inventaire réel, jamais supposées égales à celles de gk2.

## Issues (ouvertes après validation du contrat)

| Réf. | Objet | Dépend de |
|---|---|---|
| STV2-01 | Spécification et contrats JSON (#3595) | — |
| STV2-02 | Paquet `secubox-status` | 01 |
| STV2-03 | Collecteurs locaux | 02 |
| STV2-04 | Historique SQLite | 02 |
| STV2-05 | Signature et vérification | 01 |
| STV2-06 | Extension Annuaire | 01 validé, 05 |
| STV2-07 | Agrégation gk2/gk3/c3box | 03, 04, 06 |
| STV2-08 | API publique et privée | 04 |
| STV2-09 | Interface WebUI + Hall | 08 |
| STV2-10 | Incidents et disponibilité | 04, 07 |
| STV2-11 | Tests arm64/amd64 | 07, 08 |
| STV2-12 | Déploiement production | 11 |

Principes : réutiliser avant de reconstruire ; local d'abord ; provenance, complétude et fraîcheur
sont trois informations distinctes ; aucun indicateur public sans mesure, horodatage et source.
