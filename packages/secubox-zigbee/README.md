<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 📡 Zigbee Gateway

Zigbee2MQTT gateway

**Category:** IoT

## Screenshot

![Zigbee Gateway](../../docs/screenshots/vm/zigbee.png)

## Features

- Device pairing
- MQTT
- Groups
- OTA updates

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-zigbee
```

## Configuration

Configuration file: `/etc/secubox/zigbee.toml`

## API Endpoints

- `GET /api/v1/zigbee/status` - Module status
- `GET /api/v1/zigbee/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
