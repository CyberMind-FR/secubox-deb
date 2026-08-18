<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 📡 Traffic Interceptor

Network traffic interception and analysis

**Category:** Security

## Screenshot

![Traffic Interceptor](../../docs/screenshots/vm/interceptor.png)

## Features

- Packet capture
- Protocol analysis
- Session tracking
- Forensics

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-interceptor
```

## Configuration

Configuration file: `/etc/secubox/interceptor.toml`

## API Endpoints

- `GET /api/v1/interceptor/status` - Module status
- `GET /api/v1/interceptor/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
