<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-assist

SecuBox assistance request — real-time help sessions.

python3-websockets is a Recommends, not a Depends: the WS daemon needs the websockets library, but on boards where a newer websockets is provided out of band (pip, to satisfy a uvicorn version skew) the apt package is deliberately absent — a hard Depends would then block dpkg install. apt still pulls it on a normal install; dpkg -i does not enforce it. Consent-gated, audited, revocable live assistance sessions between a box and a federated center, over the wg-mesh, with a bounded action catalog and double-consent console escalation.

Paquet Debian : version `0.2.11-1~bookworm1`, architecture `all`.

## Contenu

- `api/` : API FastAPI
- `assist/` : fichiers du module
- `menu.d/` : entrée de menu
- `nft/` : fichiers du module
- `nginx/` : route nginx
- `sbin/` : exécutables
- `sudoers/` : fichiers du module
- `systemd/` : unités systemd
- `tests/` : tests
- `www/` : interface web

## Exécution

Socket Unix : `/run/secubox/assist.sock`.
- `secubox-assist-api.service` : SecuBox Assist — REST API (unix socket) (utilisateur `secubox`), lance `python3`
- `secubox-assist.service` : SecuBox Assist — WebSocket data-plane (wg-mesh only) (utilisateur `secubox-assist`), lance `python3`

## API

| Méthode | Route | Garde |
|---|---|---|
| `GET` | `/status` | require_lecture |
| `GET` | `/health` | aucune |
| `GET` | `/sessions` | require_jwt |
| `POST` | `/request` | require_jwt |
| `POST` | `/open` | require_jwt |
| `POST` | `/close` | require_jwt |
| `POST` | `/console/grant` | require_jwt |
| `POST` | `/console/revoke` | require_jwt |
| `GET` | `/offers` | require_jwt |
| `GET` | `/requests/open` | require_jwt |
| `GET` | `/delegations` | require_jwt |
| `POST` | `/delegation/assertion` | require_jwt |
| `POST` | `/request/answer` | require_jwt |
| `GET` | `/matches` | require_jwt |
| `POST` | `/offer` | require_jwt |
| `POST` | `/offer/revoke` | require_jwt |
| `POST` | `/request/open` | require_jwt |
| `POST` | `/match/accept` | require_jwt |
| `POST` | `/joinlink` | require_jwt |

Routes relevées dans le code source, relatives au montage du module. « aucune » : pas de garde déclarée à cet endroit de la route.

## Dépendances SecuBox

`secubox-annuaire`, `secubox-core`, `secubox-p2p`.

## Tests

20 fichier(s) de test. Lancer : `python3 -m pytest packages/secubox-assist`.
