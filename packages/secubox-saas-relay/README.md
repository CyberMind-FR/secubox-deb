<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🔌 SaaS Relay

SaaS / API proxy relay

**Category:** Network

## Screenshot

![SaaS Relay](../../docs/screenshots/vm/saas-relay.png)

## Features

- API proxy
- Rate limiting
- Routing
- Credentials vault

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-saas-relay
```

## Configuration

Configuration file: `/etc/secubox/saas-relay.toml`

## API Endpoints

- `GET /api/v1/saas-relay/status` - Module status
- `GET /api/v1/saas-relay/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
