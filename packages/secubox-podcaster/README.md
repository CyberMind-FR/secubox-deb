<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🎙️ Podcaster

Modern podcast manager

**Category:** Media

## Screenshot

![Podcaster](../../docs/screenshots/vm/podcaster.png)

## Features

- Feed management
- Episodes
- Transcoding
- RSS publish

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-podcaster
```

## Configuration

Configuration file: `/etc/secubox/podcaster.toml`

## API Endpoints

- `GET /api/v1/podcaster/status` - Module status
- `GET /api/v1/podcaster/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
