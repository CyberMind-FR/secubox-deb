<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 📀 System Cloner

System image cloning

**Category:** System

## Screenshot

![System Cloner](../../docs/screenshots/vm/cloner.png)

## Features

- Disk imaging
- Clone to USB
- Restore
- Compression

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-cloner
```

## Configuration

Configuration file: `/etc/secubox/cloner.toml`

## API Endpoints

- `GET /api/v1/cloner/status` - Module status
- `GET /api/v1/cloner/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
