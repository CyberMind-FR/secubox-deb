<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 💾 Backup Manager

System and LXC backup

**Category:** System

## Screenshot

![Backup Manager](../../docs/screenshots/vm/backup.png)

## Features

- Config backup
- LXC snapshots
- Restore
- Scheduling

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-backup
```

## Configuration

Configuration file: `/etc/secubox/backup.toml`

## API Endpoints

- `GET /api/v1/backup/status` - Module status
- `GET /api/v1/backup/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
