<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 💬 Matrix Server

Matrix/Synapse chat server

**Category:** Communication

## Screenshot

![Matrix Server](../../docs/screenshots/vm/matrix.png)

## Features

- E2E encryption
- Federation
- Bridges
- Calls

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-matrix
```

## Configuration

Configuration file: `/etc/secubox/matrix.toml`

## API Endpoints

- `GET /api/v1/matrix/status` - Module status
- `GET /api/v1/matrix/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
