<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-assist

SecuBox assistance request — real-time help sessions.

python3-websockets is a Recommends, not a Depends: the WS daemon needs the websockets library, but on boards where a newer websockets is provided out of band (pip, to satisfy a uvicorn version skew) the apt package is deliberately absent — a hard Depends would then block dpkg install. apt still pulls it on a normal install; dpkg -i does not enforce it. Consent-gated, audited, revocable live assistance sessions between a box and a federated center, over the wg-mesh, with double-consent console escalation. Depuis 0.4.0 le catalogue d'actions propre à l'assistance n'existe plus : voir « Un seul catalogue d'actions ».

Paquet Debian : version `0.4.0-1~trixie1`, architecture `all`.

## Contenu

- `api/` : API FastAPI
- `assist/` : fichiers du module
- `menu.d/` : entrée de menu
- `nft/` : fichiers du module
- `nginx/` : route nginx
- `sbin/` : exécutables
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
| `GET` | `/sessions` | require_jwt, rend 410 |
| `POST` | `/request` | require_jwt, rend 410 |
| `POST` | `/open` | require_jwt, rend 410 |
| `POST` | `/close` | require_jwt, rend 410 |
| `POST` | `/console/grant` | require_jwt, rend 410 |
| `POST` | `/console/revoke` | require_jwt, rend 410 |
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

## Un seul catalogue d'actions (#3126 L2, R-L2-4)

Le support passe par le **pilotage** : le maître ouvre une session de support (`POST /api/v1/pilotage/boxes/<nom>/support`),
le détenteur l'accepte en local sur la box, et les actions sont celles du ctl fermé `secubox-pilotagectl` (liste de verbes
fixe, voir `secubox-pilotage-agent`). `assist/catalog.py` est supprimé et le démon WebSocket n'exécute plus aucune action.

Les routes de session rendent **410 Gone** : `{"detail": "...", "remplace_par": "/api/v1/pilotage/boxes/<nom>/support"}`.
La garde `require_jwt` passe avant : sans authentification la réponse reste 401. Le marché (offres, demandes, appariements,
`/joinlink`) et les délégations web (`/delegations`, `/delegation/assertion`) ne changent pas.

| Action d'assist | Verbe du ctl |
|---|---|
| `service.restart <module>` | `service redemarrer <unité>` |
| `service.toggle <module>:on` | `service demarrer <unité>` |
| `service.toggle <module>:off` | `service arreter <unité>` |

Retirées, sans équivalent (le ctl reste une liste fermée) : `status.all`, `diag.collect`, `logs.tail`, `config.reload`,
`config.rollback`. L'état se lit par le relevé du pilotage (`Get`, `Device.X_SECUBOX_Releve.Mesurer()`). Un équivalent éventuel
serait un nouveau verbe du ctl, à décider là-bas. Les unités du ctl suivent sa propre règle (`secubox-<nom>.service|timer`,
hors unités protégées), non la liste `MODULE_ALLOW` de l'ancien catalogue.

La mise à niveau ne supprime aucune donnée d'assistance (journal, audits `/var/log/secubox/audit.log`). Elle retire seulement
la règle sudoers `/etc/sudoers.d/secubox-assist` (`debian/maintscript`, `rm_conffile`), qui n'avait pour utilisateur que
l'ancien dispatcher du démon ; l'unité du démon retrouve `NoNewPrivileges=true`.

## Dépendances SecuBox

`secubox-annuaire`, `secubox-core`, `secubox-p2p`.

## Tests

25 fichier(s) de test. Lancer : `python3 -m pytest packages/secubox-assist`.
