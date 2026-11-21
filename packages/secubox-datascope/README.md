<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
<!-- Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr> -->
# secubox-datascope

SBXOS DataScope V0.1 (#3853) : cockpit réseau en lecture seule. Un collecteur (minuterie 60 s) lit trois sources
locales — appareils du NAC, débits des interfaces, santé des modules — et tient à jour un graphe d'entités
(`node`, `network`, `interface`, `device`, `ip`, `service`) et de relations (`BELONGS_TO`, `CONNECTS_TO`,
`HOSTED_ON`, `OBSERVED_BY`) observées ou rapportées, jamais inférées. Aucun nom de domaine n'est stocké.

## Contenu du paquet (tâche 1 : squelette)

| Élément | Rôle |
|---|---|
| `secubox-datascope.service` | API FastAPI/Uvicorn sur `/run/secubox/datascope.sock` (`0660`, groupe `secubox`) |
| `secubox-datascope-collect.{service,timer}` | passe de collecte, minuterie 60 s, `Nice=10`, `CPUQuota=25%`, I/O idle |
| `nginx/datascope.conf` | route `/api/v1/datascope/` vers la socket (routes WAF : `/etc/nginx/secubox-routes.d/`) |
| `apparmor/secubox-datascope` | profil `enforce` : lecture des sources, écriture base, cache et socket |
| `conf/datascope.toml` | `/etc/secubox/datascope.toml` (`[stockage]`, `[sources]`) |

## API (`/api/v1/datascope/`)

| Route | Garde | Réponse |
|---|---|---|
| `GET health` | publique | `{"status": "ok", "module": "datascope", "version": "0.1.0"}` |
| `GET status` | `require_lecture` | `{"module", "base": "ok"\|"absente", "derniere_passe"}` |

## Configuration

Ordre de priorité : variables d'environnement (`SECUBOX_DATASCOPE_DB`, `_CACHE`, `_NAC_DB`, `_NETSTATS`,
`_MODULES`) > `/etc/secubox/datascope.toml` > défauts. Le postinst choisit
`/data/secubox-datascope/datascope.db` si `/data` est un point de montage, sinon
`/var/lib/secubox-datascope/datascope.db`.

Depends : `python3-fastapi`, `python3-uvicorn`, `secubox-core`. Compte `secubox-datascope`, groupe `secubox`.
