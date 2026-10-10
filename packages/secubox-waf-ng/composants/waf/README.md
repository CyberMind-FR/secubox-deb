<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🔥 Web Application Firewall

WAF with 300+ OWASP security rules

**Category:** Security

## Screenshot

![Web Application Firewall](../../docs/screenshots/vm/waf.png)

## Features

- OWASP rules
- Custom rules
- Request logging

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-waf
```

## Configuration

Configuration file: `/etc/secubox/waf.toml`

## API Endpoints

- `GET /api/v1/waf/status` - Module status
- `GET /api/v1/waf/health` - Health check
- `GET /api/v1/waf/enforcement[?statut=active|expired|released]` - actions défensives (bans de sbxwaf) : type, cible, raison, durée, échéance, rollback (#2240)
- `GET /api/v1/waf/enforcement/mode` - `PASSIVE_ONLY` / `SIMULATION` / `ACTIVE`, par source (acteurs, campagnes) et global
- `GET /api/v1/waf/decisions` - décisions des bans automatiques : `BLOCKED`, `WOULD_BLOCK` (simulation), `OBSERVE` (écarté, avec le motif)
- `POST /api/v1/waf/enforcement/{id}/rollback` - annule une action active (retire l'adresse du set nft), audité dans `/var/log/secubox/audit.log` ; `require_jwt`

Les trois lectures (`require_lecture`) relisent les fichiers de sbxwaf (`bans.jsonl`, `actor-ban-etat.json`, `campagne-ban-etat.json`) ; rien n'est recopié.

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
