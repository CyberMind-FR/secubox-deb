<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🌐 Exposure Settings

Unified exposure management

**Category:** Privacy

## Screenshot

![Exposure Settings](../../docs/screenshots/vm/exposure.png)

## Features

- Tor exposure
- SSL certs
- DNS records
- Mesh access

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-exposure
```

## Configuration

Configuration file: `/etc/secubox/exposure.toml`

## API Endpoints

- `GET /api/v1/exposure/status` - Module status
- `GET /api/v1/exposure/health` - Health check

## License

MIT License - CyberMind © 2024-2026
