<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-system-hub

SecuBox System Hub Dashboard.

System control center: health, systemd services, journald logs, diagnostics.

Debian bookworm port of luci-app-system-hub (SecuBox OpenWrt / CyberMind.fr).

Paquet Debian : version `1.0.2-1~bookworm1`, architecture `all`.

## Contenu

- `api/` : API FastAPI

## Exécution

Socket Unix : `/run/secubox/system-hub.sock`.

## API

| Méthode | Route | Garde |
|---|---|---|
| `GET` | `/status` | require_lecture |
| `GET` | `/health` | aucune |
| `GET` | `/stats` | require_jwt |
| `GET` | `/system` | require_jwt |
| `GET` | `/health/summary` | require_jwt |
| `GET` | `/services` | require_jwt |
| `GET` | `/services/{service_name}` | require_jwt |
| `POST` | `/services/{service_name}/{action}` | require_jwt |
| `GET` | `/support/settings` | require_jwt |
| `PUT` | `/support/settings` | require_jwt |
| `GET` | `/support/remote` | require_jwt |
| `POST` | `/support/remote/{action}` | require_jwt |
| `GET` | `/diagnostics` | require_jwt |
| `POST` | `/diagnostics/collect` | require_jwt |
| `GET` | `/diagnostics/{bundle_id}/download` | require_jwt |
| `POST` | `/diagnostics/{bundle_id}/upload` | require_jwt |
| `DELETE` | `/diagnostics/{bundle_id}` | require_jwt |
| `GET` | `/cached-status` | require_lecture |
| `GET` | `/metrics/history` | require_jwt |
| `POST` | `/metrics/record` | require_jwt |
| `POST` | `/metrics/cleanup` | require_jwt |
| `POST` | `/diagnostics/cleanup` | require_jwt |
| `GET` | `/services/{service_name}/logs` | require_jwt |
| `GET` | `/disk` | require_jwt |
| `GET` | `/network/stats` | require_jwt |
| `POST` | `/services/restart-all` | require_jwt |

Routes relevées dans le code source, relatives au montage du module. « aucune » : pas de garde déclarée à cet endroit de la route.

## Dépendances SecuBox

`secubox-core`.
