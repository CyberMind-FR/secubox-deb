<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🍪 Cookie Manager

Cookie and session security management

**Category:** Security

## Screenshot

![Cookie Manager](../../docs/screenshots/vm/cookies.png)

## Features

- Cookie policies
- Session security
- SameSite enforcement
- Audit

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-cookies
```

## Configuration

Configuration file: `/etc/secubox/cookies.toml`

## API Endpoints

- `GET /api/v1/cookies/status` - Module status
- `GET /api/v1/cookies/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
