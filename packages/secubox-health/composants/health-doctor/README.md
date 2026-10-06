<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-health-doctor

SecuBox vital-services health monitor.

Daemon + CLI (healthctl) + FastAPI that runs periodic checks against the vital services on a SecuBox board (haproxy, sbxwaf, gitea LXC, nginx, mail LXC, metrics socket, cookie-audit ledger freshness, filesystems, act-runner). State transitions emit CSPN-compatible journal events. Read-only API consumed by the portal banner.

Paquet Debian : version `1.2.0-1~bookworm1`, architecture `all`.

## Contenu

- `api/` : API FastAPI
- `sbin/` : exécutables
- `systemd/` : unités systemd
- `tests/` : tests

## Exécution

Socket Unix : `/run/secubox/health-doctor.sock`, `/run/secubox/metrics.sock`.
- `secubox-health-doctor-runner.service` : SecuBox health-doctor — periodic check pass (#212) (utilisateur `secubox`), lance `python3`
- `secubox-health-doctor-runner.timer` : SecuBox health-doctor — run vital-services checks every minute (#212)
- `secubox-health-doctor.service` : SecuBox vital-services health monitor (#212) (utilisateur `secubox`), lance `python3`

## API

| Méthode | Route | Garde |
|---|---|---|
| `GET` | `/health` | aucune |
| `GET` | `/checks` | require_lecture |
| `GET` | `/status/{name}` | require_lecture |
| `POST` | `/run` | require_jwt |
| `POST` | `/waf-selftest/run` | require_jwt |
| `GET` | `/registered` | require_lecture |

Routes relevées dans le code source, relatives au montage du module. « aucune » : pas de garde déclarée à cet endroit de la route.

## Dépendances SecuBox

`secubox-core`.

## Tests

2 fichier(s) de test. Lancer : `python3 -m pytest packages/secubox-health-doctor`.
