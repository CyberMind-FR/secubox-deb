<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🖥️ RustDesk

Self-hosted remote desktop relay

**Category:** Access

## Screenshot

![RustDesk](../../docs/screenshots/vm/rustdesk.png)

## Features

- Relay server
- ID server
- Sessions
- Self-hosted

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-rustdesk
```

## Configuration

Configuration file: `/etc/secubox/rustdesk.toml`

## API Endpoints

- `GET /api/v1/rustdesk/status` - Module status
- `GET /api/v1/rustdesk/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
