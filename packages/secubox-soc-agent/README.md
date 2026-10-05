<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-soc-agent

SecuBox SOC Agent — Edge Node Agent for SOC Integration.

Edge node agent that collects system metrics and security alerts, then pushes them to an upstream SOC gateway for centralized monitoring.

Features: - System metrics collection (CPU, memory, disk, network) - Security alert aggregation (Suricata, WAF) - HMAC-SHA256 signed metric push to upstream SOC - Remote command execution with signature validation - Automatic enrollment with SOC gateway - Command audit logging

Part of the SecuBox hierarchical SOC architecture.

Paquet Debian : version `1.0.2-1~bookworm1`, architecture `all`.

## Contenu

- `api/` : API FastAPI
- `lib/` : fichiers du module

## Exécution

Socket Unix : `/run/secubox/soc-agent.sock`.
- `secubox-soc-agent.service` : SecuBox SOC Agent (utilisateur `secubox-soc-agent`), lance `python3`

## API

| Méthode | Route | Garde |
|---|---|---|
| `GET` | `/status` | require_lecture |
| `GET` | `/health` | aucune |
| `GET` | `/metrics` | require_lecture |
| `GET` | `/alerts` | require_lecture |
| `GET` | `/report` | require_lecture |
| `POST` | `/command` | aucune |
| `GET` | `/command/allowed` | require_lecture |
| `POST` | `/enroll` | require_jwt |
| `POST` | `/unenroll` | require_jwt |
| `GET` | `/upstream/status` | require_jwt |
| `POST` | `/upstream/test` | require_jwt |
| `POST` | `/upstream/push` | require_jwt |
| `POST` | `/config` | require_jwt |
| `GET` | `/config` | require_jwt |
| `GET` | `/audit` | require_jwt |

Routes relevées dans le code source, relatives au montage du module. « aucune » : pas de garde déclarée à cet endroit de la route.

## Dépendances SecuBox

`secubox-core`.
