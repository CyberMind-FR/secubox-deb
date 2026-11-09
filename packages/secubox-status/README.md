<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-status — Status Live v2, jalon 1

Supervision locale de l'appliance, en lecture seule. Spécification : `docs/superpowers/specs/2026-11-09-status-live-v2.md` (#3595) ; jalon 1 : #3605.

## Ce que fait le paquet

- **Collecte** (`secubox-status-collect.timer`, toutes les 60 s) : lit les caches existants, sans lancer de commande.
  - `/var/cache/secubox/health/status.json` (sondes des vhosts), périmé après 300 s ;
  - `/var/cache/secubox/health/modules.json` (santé des modules), périmé après 300 s ;
  - `/var/lib/secubox/profiles/validation/releve.json` (validation du profil), périmé après 900 s ;
  - `/proc` et `/sys` (processeur, mémoire, disque, charge, durée de marche, température).
- **Normalisation** : états `operational`, `degraded`, `outage`, `maintenance`, `unknown`. Une source absente,
  périmée ou illisible vaut `unknown`, jamais une panne ni un succès. Un module se juge sur sa couche API
  (un module servi par l'agrégateur a une unité systemd inactive par construction). Un module critique
  indisponible rend l'appliance indisponible ; un module optionnel la dégrade seulement.
- **Historique** : `/var/lib/secubox-status/status.db` (SQLite WAL), 90 jours.
- **Projection publique** : `/var/lib/secubox-status/public/public-v2.json`, liste blanche de champs (ni noyau, ni
  nom d'hôte, ni ressources, ni inventaire des modules sauf réglage explicite). Servie en statique au jalon 3.

## API (`/run/secubox/status.sock`, route nginx `/api/v1/status/`)

| Méthode | Route | Garde |
|---|---|---|
| GET | `/health` | sonde publique |
| GET | `/status`, `/summary`, `/history?heures=24` | `require_lecture` |
| GET | `/admin/snapshot`, `/admin/sources` | `require_jwt` |

Aucune route mutante. L'API ne collecte jamais : elle relit les fichiers du collecteur.

## Configuration

`/etc/secubox/status.toml` (semé une fois depuis `/usr/share/secubox/status/status.toml.example`) : identifiant
d'affichage du nœud, rétention, chemins et seuils de fraîcheur des sources, champs publics.

## Sécurité

Compte dédié `secubox-status` (groupe `secubox`, sans shell). Unités durcies : aucune capacité, aucun réseau IP
(`AF_UNIX` seul), `ProtectSystem=strict`, écriture limitée à `/var/lib/secubox-status` (`StateDirectory`, hors de
l'arbre partagé `/var/lib/secubox`) et à la socket. Caches lus sans suivre de lien, 8 Mio au plus.

## Hors jalon 1

Signature Ed25519 et fédération par l'Annuaire (jalon 2), page publique, exposition HAProxy et sondes externes
(jalon 3), incidents (jalon 3-4).
