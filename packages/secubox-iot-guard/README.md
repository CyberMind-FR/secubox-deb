<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🔌 IoT Guard

IoT device security monitoring

**Category:** Security

## Screenshot

![IoT Guard](../../docs/screenshots/vm/iot-guard.png)

## Features

- Device fingerprinting
- Anomaly detection
- Isolation
- Firmware checks

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-iot-guard
```

## Configuration

Configuration file: `/etc/secubox/iot-guard.toml`

## API Endpoints

- `GET /api/v1/iot-guard/status` - Module status
- `GET /api/v1/iot-guard/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
