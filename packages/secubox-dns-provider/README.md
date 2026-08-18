<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🌐 DNS Provider

External DNS provider integration

**Category:** DNS

## Screenshot

![DNS Provider](../../docs/screenshots/vm/dns-provider.png)

## Features

- Cloudflare
- Route53
- DigitalOcean
- Dynamic DNS

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-dns-provider
```

## Configuration

Configuration file: `/etc/secubox/dns-provider.toml`

## API Endpoints

- `GET /api/v1/dns-provider/status` - Module status
- `GET /api/v1/dns-provider/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
