<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-devwatch

DevWatch — live upstream-GitHub development watch for SecuBox.

A personal-but-shareable cardlet + vhost service that turns a GitHub repo's live pulse into pertinent, vulgarized metrics: real-time cadence, efficiency arrows, cumulative dev-time, latest commits and release link, plus an emancipation layer (estimated cost, carbon equivalent, perpetual funding campaign). Facts come only from the public GitHub API; the derived figures are clearly labelled estimations, and operator-entered static flows (expenses, sponsorship, subscriptions) are captured through a JWT admin panel.

FastAPI backend on /api/v1/devwatch/ over a Unix socket; a background poller caches a ready-to-serve summary (double-cache pattern); the browser only ever talks to the box (same origin), never to GitHub.

Paquet Debian : version `1.1.0-1~bookworm1`, architecture `all`.

## Contenu

- `api/` : API FastAPI
- `conf/` : configuration livrée
- `menu.d/` : entrée de menu
- `nginx/` : route nginx
- `systemd/` : unités systemd
- `tests/` : tests
- `www/` : interface web

## Exécution

Socket Unix : `/run/secubox/devwatch.sock`.
- `secubox-devwatch.service` : SecuBox DevWatch API (live upstream-GitHub development watch) [#1370] (utilisateur `secubox`), lance `python3`

## API

| Méthode | Route | Garde |
|---|---|---|
| `GET` | `/health` | aucune |
| `GET` | `/summary` | require_lecture |
| `GET` | `/issues` | require_lecture |
| `GET` | `/modules` | require_lecture |
| `GET` | `/flows` | require_lecture |
| `POST` | `/flows` | require_jwt |
| `GET` | `/config` | require_jwt |
| `POST` | `/config/token` | require_jwt |
| `POST` | `/config` | require_jwt |
| `POST` | `/refresh` | require_jwt |

Routes relevées dans le code source, relatives au montage du module. « aucune » : pas de garde déclarée à cet endroit de la route.

## Dépendances SecuBox

`secubox-core`, `secubox-sbxui`.

## Tests

1 fichier(s) de test. Lancer : `python3 -m pytest packages/secubox-devwatch`.
