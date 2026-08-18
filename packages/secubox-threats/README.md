<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# ⚠️ Threat Dashboard

Unified threat visualization

**Category:** Security

## Screenshot

![Threat Dashboard](../../docs/screenshots/vm/threats.png)

## Features

- Threat feeds
- Attack timeline
- Severity levels
- Correlation

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-threats
```

## Configuration

Configuration file: `/etc/secubox/threats.toml`

## API Endpoints

- `GET /api/v1/threats/status` - Module status
- `GET /api/v1/threats/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
