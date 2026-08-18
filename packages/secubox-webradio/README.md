<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 📻 Web Radio

Internet radio streaming

**Category:** Media

## Screenshot

![Web Radio](../../docs/screenshots/vm/webradio.png)

## Features

- Radio stations
- Recording
- Schedule
- Favorites

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-webradio
```

## Configuration

Configuration file: `/etc/secubox/webradio.toml`

## API Endpoints

- `GET /api/v1/webradio/status` - Module status
- `GET /api/v1/webradio/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
