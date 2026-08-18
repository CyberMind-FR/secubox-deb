<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 📧 Mail Server

Postfix/Dovecot mail server

**Category:** Email

## Screenshot

![Mail Server](../../docs/screenshots/vm/mail.png)

## Features

- Domains
- Mailboxes
- DKIM
- SpamAssassin
- ClamAV

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-mail
```

## Configuration

Configuration file: `/etc/secubox/mail.toml`

## API Endpoints

- `GET /api/v1/mail/status` - Module status
- `GET /api/v1/mail/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
