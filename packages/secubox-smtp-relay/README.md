<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 📤 SMTP Relay

SMTP relay and smarthost

**Category:** Email

## Screenshot

![SMTP Relay](../../docs/screenshots/vm/smtp-relay.png)

## Features

- Relay
- Authentication
- Rate limiting
- Logging

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-smtp-relay
```

## Configuration

Configuration file: `/etc/secubox/smtp-relay.toml`

## API Endpoints

- `GET /api/v1/smtp-relay/status` - Module status
- `GET /api/v1/smtp-relay/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
