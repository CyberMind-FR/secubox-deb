<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🖥️ RTTY Console

Remote terminal access

**Category:** System

## Screenshot

![RTTY Console](../../docs/screenshots/vm/rtty.png)

## Features

- Web terminal
- SSH
- File transfer
- Recording

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-rtty
```

## Configuration

Configuration file: `/etc/secubox/rtty.toml`

## API Endpoints

- `GET /api/v1/rtty/status` - Module status
- `GET /api/v1/rtty/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
