<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 💌 Webmail

Roundcube/SOGo webmail

**Category:** Email

## Screenshot

![Webmail](../../docs/screenshots/vm/webmail.png)

## Features

- Web interface
- Address book
- Calendar
- Mobile

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-webmail
```

## Configuration

Configuration file: `/etc/secubox/webmail.toml`

## API Endpoints

- `GET /api/v1/webmail/status` - Module status
- `GET /api/v1/webmail/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
