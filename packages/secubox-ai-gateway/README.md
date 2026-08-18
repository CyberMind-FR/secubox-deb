<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🚪 AI Gateway

AI model API gateway

**Category:** AI

## Screenshot

![AI Gateway](../../docs/screenshots/vm/ai-gateway.png)

## Features

- Rate limiting
- Load balancing
- Caching
- Logging

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-ai-gateway
```

## Configuration

Configuration file: `/etc/secubox/ai-gateway.toml`

## API Endpoints

- `GET /api/v1/ai-gateway/status` - Module status
- `GET /api/v1/ai-gateway/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
