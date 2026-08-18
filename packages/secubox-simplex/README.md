<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 💬 SimpleX Chat

Privacy-focused messaging

**Category:** Privacy

## Screenshot

![SimpleX Chat](../../docs/screenshots/vm/simplex.png)

## Features

- E2E encryption
- No user IDs
- Self-hosted
- Groups

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-simplex
```

## Configuration

Configuration file: `/etc/secubox/simplex.toml`

## API Endpoints

- `GET /api/v1/simplex/status` - Module status
- `GET /api/v1/simplex/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
