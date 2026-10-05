<!-- SPDX-License-Identifier: LicenseRef-CMSD-1.0 -->
# secubox-soc-web

SecuBox SOC Web Dashboard — Browser-based Fleet Monitoring.

React-based web dashboard for the SecuBox Security Operations Center. Provides real-time fleet monitoring, alert visualization, and remote node management through a modern web interface.

Features: - Fleet overview with node health grid - Real-time alert stream via WebSocket - Cross-node threat correlation visualization - Remote service management (start/stop/restart) - Threat intelligence map - Cyberpunk-themed responsive UI

Part of the SecuBox hierarchical SOC architecture.

Paquet Debian : version `1.1.3-2~bookworm1`, architecture `all`.

## Contenu

- `public/` : fichiers du module
- `src/` : fichiers du module

## Exécution

Socket Unix : `/run/secubox/soc-gateway.sock`.
