# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
# secubox-garde — détecteur d'intrusion, d'évasion et d'infection (#3794)

Répondeur automatique : une menace détectée devient une décision (`decisions`), appliquée sans attendre
l'administrateur, notifiée, puis levée ou échue. Ce premier jalon pose le squelette : paquet, unités,
profil AppArmor, base SQLite (WAL) et réglages. Moteur, sources, notifications et page viennent ensuite.

## Fichiers

- Base : `/var/lib/secubox/garde/garde.db` — tables `decisions`, `positions`, `liberations`, `file_notifs`, `recidives`.
- Réglages : `/etc/secubox/garde.toml` (semé une fois, 0640 root:secubox). Défauts : `automatique = true`,
  `courriel = ""`, `sms_utilisateur = ""`, `sms_bans = false`, `quarantaines_max = 3`, `rafale_bans = 50`.
- Secret d'envoi des SMS : `/etc/secubox/secrets/garde-sms` (0600), jamais dans le TOML.

## API (`/run/secubox/garde.sock`, route nginx `/api/v1/garde/`)

| Méthode | Route | Garde |
|---|---|---|
| GET | `/health` | ouverte |
| GET | `/etat` | `require_lecture` |

## Unités

`secubox-garde.service` (API, compte `secubox-garde`), `secubox-garde-passage.service` + `.timer`
(passage du moteur toutes les 60 s ; sans effet tant que le moteur n'est pas livré).

## Sources (capteurs)

`garde/sources.py` lit : `/var/lib/secubox/dns-guard/alerts.jsonl` (incrémental, inode + offset),
`/run/secubox/actord-propositions.json`, `ip -j neigh` (IP → MAC) et la liste DoH d'ad-guard
(`/usr/share/secubox/ad-guard/lists/resolveurs-doh.txt`, noms seulement). Requêtes DNS par client
pour la détection DoH : table `dnstv_recents` de `/var/lib/secubox/ad-guard/dnstv/dnstv.db`
(ad-guard, lecture seule). Le compte `secubox-garde` doit lire ce fichier (groupe `secubox`, dossier
traversable, `-shm` ouvrable en WAL) ; sans ces droits la lecture renvoie une liste vide.
