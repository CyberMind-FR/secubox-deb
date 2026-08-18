<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# ⚡ HAProxy

Load balancer with TLS 1.3

**Category:** Network

## Screenshot

![HAProxy](../../docs/screenshots/vm/haproxy.png)

## Features

- Backend management
- Stats
- ACLs
- SSL termination
- Health checks

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-haproxy
```

## Configuration

Configuration file: `/etc/secubox/haproxy.toml`

## API Endpoints

- `GET /api/v1/haproxy/status` - Module status
- `GET /api/v1/haproxy/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
