<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-courbes

Courbes (`/grafana/`, remplace Grafana) et Glances (`/glances/`) de SecuBox, **sans** `secubox-metrics` (#2865).

- **Relevé** : `secubox-courbes-serie.timer`, une fois par minute, 7 jours dans `/var/lib/secubox/metrics/series.jsonl` (compteurs bruts : un redémarrage donne un trou, jamais un pic).
- **API** (lecture, servie par `secubox-groupd`, routes à la racine, joignables en `/api/v1/courbes/…`) : `GET /series?duree=<s>|depuis=&jusqua=&points=`, `GET /systeme` (instantané : CPU par cœur, mémoire, disques, réseau, températures, top des processus), `GET /health`.
- **Bibliothèque** `secubox_courbes` (`serie`, `systeme`) : stdlib et `psutil`. `secubox-metrics` la réutilise pour `/api/v1/metrics/series` et `/systeme`.
- Coût : aucun processus de plus (groupe `groupd`), une courte tâche par minute.
