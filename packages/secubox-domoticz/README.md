<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🏠 Domoticz

Home automation

**Category:** IoT

## Screenshot

![Domoticz](../../docs/screenshots/vm/domoticz.png)

## Features

- Devices
- Scenes
- Scripts
- History

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-domoticz
```

## Configuration

Configuration file: `/etc/secubox/domoticz.toml`

## API Endpoints

- `GET /api/v1/domoticz/status` - Module status
- `GET /api/v1/domoticz/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
