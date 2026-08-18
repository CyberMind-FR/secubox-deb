<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🐘 GoToSocial

ActivityPub social server

**Category:** Publishing

## Screenshot

![GoToSocial](../../docs/screenshots/vm/gotosocial.png)

## Features

- Mastodon compatible
- Federation
- Media
- Privacy

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-gotosocial
```

## Configuration

Configuration file: `/etc/secubox/gotosocial.toml`

## API Endpoints

- `GET /api/v1/gotosocial/status` - Module status
- `GET /api/v1/gotosocial/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
