<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🏡 Home Assistant

Home automation hub

**Category:** IoT

## Screenshot

![Home Assistant](../../docs/screenshots/vm/homeassistant.png)

## Features

- Integrations
- Automations
- Dashboard
- Voice

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-homeassistant
```

## Configuration

Configuration file: `/etc/secubox/homeassistant.toml`

## API Endpoints

- `GET /api/v1/homeassistant/status` - Module status
- `GET /api/v1/homeassistant/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
