<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 📡 CyberFeed

RSS/Atom feed aggregator

**Category:** Publishing

## Screenshot

![CyberFeed](../../docs/screenshots/vm/cyberfeed.png)

## Features

- Feed management
- Categories
- Search
- Export

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-cyberfeed
```

## Configuration

Configuration file: `/etc/secubox/cyberfeed.toml`

## API Endpoints

- `GET /api/v1/cyberfeed/status` - Module status
- `GET /api/v1/cyberfeed/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
