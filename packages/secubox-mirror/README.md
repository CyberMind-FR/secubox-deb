<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🪞 Mirror Manager

APT mirror management

**Category:** System

## Screenshot

![Mirror Manager](../../docs/screenshots/vm/mirror.png)

## Features

- Mirror sync
- Bandwidth
- Scheduling
- Cache

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-mirror
```

## Configuration

Configuration file: `/etc/secubox/mirror.toml`

## API Endpoints

- `GET /api/v1/mirror/status` - Module status
- `GET /api/v1/mirror/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
