<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🎬 Media Flow

Media traffic analytics

**Category:** Monitoring

## Screenshot

![Media Flow](../../docs/screenshots/vm/mediaflow.png)

## Features

- Stream detection
- Bandwidth usage
- Protocol analysis
- QoE

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-mediaflow
```

## Configuration

Configuration file: `/etc/secubox/mediaflow.toml`

## API Endpoints

- `GET /api/v1/mediaflow/status` - Module status
- `GET /api/v1/mediaflow/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
