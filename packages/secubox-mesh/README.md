<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🕸️ Mesh Network

Mesh networking with Yggdrasil

**Category:** VPN

## Screenshot

![Mesh Network](../../docs/screenshots/vm/mesh.png)

## Features

- Peer discovery
- Routing
- Encryption
- IPv6 overlay

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-mesh
```

## Configuration

Configuration file: `/etc/secubox/mesh.toml`

## API Endpoints

- `GET /api/v1/mesh/status` - Module status
- `GET /api/v1/mesh/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
