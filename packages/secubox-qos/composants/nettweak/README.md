<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🔧 Network Tweaks

Network kernel parameters tuning

**Category:** Network

## Screenshot

![Network Tweaks](../../docs/screenshots/vm/nettweak.png)

## Features

- TCP tuning
- Buffer sizes
- Congestion control
- Profiles

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-nettweak
```

## Configuration

Configuration file: `/etc/secubox/nettweak.toml`

## API Endpoints

- `GET /api/v1/nettweak/status` - Module status
- `GET /api/v1/nettweak/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
