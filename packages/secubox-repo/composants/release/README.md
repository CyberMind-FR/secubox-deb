<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-release

SecuBox release-rings — reprepro-copy promotion actuator.

Op-gated argv builders for promoting packages between apt repo rings (draft/internal/published) via reprepro copy, with a hard arm64 guard: an evolution carrying deb artifacts with no arm64 build is refused, never published amd64-only (arm64 is the only production arch and would otherwise be bricked).

Paquet Debian : version `0.1.3-1~bookworm1`, architecture `all`.

## Contenu

- `api/` : API FastAPI
- `menu.d/` : entrée de menu
- `nginx/` : route nginx
- `release/` : fichiers du module
- `sbin/` : exécutables
- `sudoers/` : fichiers du module
- `systemd/` : unités systemd
- `tests/` : tests
- `www/` : interface web

## Exécution

Socket Unix : `/run/secubox/release.sock`.
- `secubox-release-api.service` : SecuBox Release Rings — REST API (unix socket) (utilisateur `secubox`), lance `python3`

## API

| Méthode | Route | Garde |
|---|---|---|
| `GET` | `/status` | require_lecture |
| `GET` | `/health` | aucune |
| `GET` | `/evolutions` | require_jwt |
| `GET` | `/box-ring` | require_jwt |
| `POST` | `/publish` | require_jwt |
| `POST` | `/promote` | require_jwt |
| `POST` | `/demote` | require_jwt |
| `POST` | `/assign` | require_jwt |

Routes relevées dans le code source, relatives au montage du module. « aucune » : pas de garde déclarée à cet endroit de la route.

## Dépendances SecuBox

`secubox-annuaire`, `secubox-core`.

## Tests

6 fichier(s) de test. Lancer : `python3 -m pytest packages/secubox-release`.
