<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 📊 Netdata

Real-time system monitoring

**Category:** Monitoring

## Screenshot

![Netdata](../../docs/screenshots/vm/netdata.png)

## Features

- Metrics
- Alerts
- Charts
- Plugins

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-netdata
```

## Configuration

Configuration file: `/etc/secubox/netdata.toml`

## API Endpoints

- `GET /api/v1/netdata/status` - Module status
- `GET /api/v1/netdata/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
