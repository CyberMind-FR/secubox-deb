<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-media

SecuBox External Media Manager.

Port Debian bookworm du module luci-app-media de SecuBox OpenWrt. Provides FastAPI backend on /api/v1/media/ via Unix socket.

Paquet Debian : version `1.6.0-1~bookworm1`, architecture `all`.

## Contenu

- `api/` : API FastAPI
- `etc/` : fichiers du module
- `menu.d/` : entrée de menu
- `nginx/` : route nginx
- `sbin/` : exécutables
- `tests/` : tests
- `www/` : interface web

## Exécution

Socket Unix : `/run/secubox/media.sock`.
- `secubox-media-automount.service` : SecuBox Media — montage des supports mémorisés au démarrage, lance `mediactl`
- `secubox-media-drain.service` : SecuBox Médias externes — drainage de la file de transfert, lance `mediactl`
- `secubox-media-drain.timer` : SecuBox Médias externes — drainage périodique de la file
- `secubox-media.service` : SecuBox Media API (utilisateur `secubox`), lance `python3`

## API

| Méthode | Route | Garde |
|---|---|---|
| `GET` | `/health` | aucune |
| `GET` | `/detect` | require_lecture |
| `GET` | `/browse` | require_lecture |
| `GET` | `/roots` | require_lecture |
| `POST` | `/mount` | require_jwt |
| `POST` | `/automount` | require_jwt |
| `POST` | `/unmount` | require_jwt |
| `POST` | `/copy` | require_jwt |
| `POST` | `/sync` | require_jwt |
| `POST` | `/compare` | require_jwt |
| `GET` | `/jobs` | require_lecture |

Routes relevées dans le code source, relatives au montage du module. « aucune » : pas de garde déclarée à cet endroit de la route.

## Dépendances SecuBox

`secubox-core`.

## Tests

1 fichier(s) de test. Lancer : `python3 -m pytest packages/secubox-media`.
