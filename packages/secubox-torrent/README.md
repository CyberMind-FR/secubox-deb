<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🌊 Torrent

BitTorrent client

**Category:** Media

## Screenshot

![Torrent](../../docs/screenshots/vm/torrent.png)

## Features

- Downloads
- RSS
- Remote control
- Bandwidth limits

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-torrent
```

## Configuration

Configuration file: `/etc/secubox/torrent.toml`

## API Endpoints

- `GET /api/v1/torrent/status` - Module status
- `GET /api/v1/torrent/health` - Health check

## License

MIT License - CyberMind © 2024-2026
