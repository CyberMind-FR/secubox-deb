<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-soc-gateway

SecuBox SOC Gateway — Central Fleet Monitoring Hub.

Central SOC aggregation gateway that receives metrics from edge nodes, provides unified alert streams, correlates threats across the fleet, and enables remote node management.

Features: - Node registration with enrollment tokens - Fleet-wide metrics aggregation - Unified alert stream from all nodes - Cross-node threat correlation - Remote command execution - WebSocket real-time updates - Hierarchical deployment support (regional/central)

Part of the SecuBox hierarchical SOC architecture.

Paquet Debian : version `1.1.1-1~bookworm1`, architecture `all`.

## Contenu

- `api/` : API FastAPI
- `lib/` : fichiers du module

## Exécution

Socket Unix : `/run/secubox/soc-gateway.sock`.
- `secubox-soc-gateway.service` : SecuBox SOC Gateway (utilisateur `secubox-soc-gateway`), lance `python3`

## API

| Méthode | Route | Garde |
|---|---|---|
| `GET` | `/status` | require_lecture |
| `GET` | `/health` | aucune |
| `POST` | `/enroll` | aucune |
| `POST` | `/ingest` | aucune |
| `GET` | `/fleet/summary` | require_jwt |
| `GET` | `/fleet/nodes` | require_jwt |
| `GET` | `/fleet/nodes/{node_id}` | require_jwt |
| `DELETE` | `/fleet/nodes/{node_id}` | require_jwt |
| `GET` | `/alerts/stream` | require_jwt |
| `GET` | `/alerts/correlated` | require_jwt |
| `GET` | `/alerts/correlation-summary` | require_jwt |
| `POST` | `/nodes/{node_id}/command` | require_jwt |
| `POST` | `/nodes/{node_id}/services/{service}/action` | require_jwt |
| `POST` | `/broadcast` | require_jwt |
| `GET` | `/commands` | require_jwt |
| `GET` | `/commands/{cmd_id}` | require_jwt |
| `POST` | `/tokens` | require_jwt |
| `POST` | `/tokens/cleanup` | require_jwt |
| `GET` | `/hierarchy/status` | require_jwt |
| `POST` | `/hierarchy/mode` | require_jwt |
| `POST` | `/regional/token` | require_jwt |
| `POST` | `/regional/enroll` | aucune |
| `POST` | `/regional/ingest` | aucune |
| `GET` | `/regional/socs` | require_jwt |
| `POST` | `/upstream/enroll` | require_jwt |
| `GET` | `/upstream/status` | require_jwt |
| `GET` | `/global/summary` | require_jwt |
| `GET` | `/global/regions` | require_jwt |
| `GET` | `/global/threats` | require_jwt |
| `POST` | `/global/cleanup` | require_jwt |

Routes relevées dans le code source, relatives au montage du module. « aucune » : pas de garde déclarée à cet endroit de la route.

## Dépendances SecuBox

`secubox-core`.
