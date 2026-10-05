<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-appstore

SecuBox App Store — module catalog & lifecycle (Phase A).

Categorized, tiered, searchable catalog of SecuBox modules with live install/run state, served as a hub web UI. Phase A is read-only; install, enable/disable, preferences and profiles arrive in later phases via a privileged worker.

Paquet Debian : version `0.4.23-1~bookworm1`, architecture `all`.

## Contenu

- `api/` : API FastAPI
- `menu.d/` : entrée de menu
- `nginx/` : route nginx
- `sbin/` : exécutables
- `scripts/` : scripts
- `www/` : interface web

## Exécution

Socket Unix : `/run/secubox/appstore.sock`.
- `secubox-appstore.service` : SecuBox App Store — module catalog API (utilisateur `secubox`), lance `python3`

## API

| Méthode | Route | Garde |
|---|---|---|
| `GET` | `/health` | aucune |
| `GET` | `/categories` | require_lecture |
| `GET` | `/catalog` | require_lecture |
| `GET` | `/mesh-catalog` | require_lecture |
| `GET` | `/module/{name}` | require_lecture |
| `GET` | `/module/{name}/check` | require_lecture |
| `GET` | `/groupes` | require_lecture |
| `GET` | `/metapaquets` | require_lecture |
| `GET` | `/profils` | require_lecture |
| `POST` | `/module/{name}/action/{verb}` | require_jwt |
| `GET` | `/module/{name}/config` | require_lecture |
| `PUT` | `/module/{name}/config` | require_jwt |

Routes relevées dans le code source, relatives au montage du module. « aucune » : pas de garde déclarée à cet endroit de la route.

## Dépendances SecuBox

`secubox-core`.
