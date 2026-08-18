<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🛡️ DNS Guard

DNS-based threat protection

**Category:** DNS

## Screenshot

![DNS Guard](../../docs/screenshots/vm/dns-guard.png)

## Features

- Malware blocking
- Phishing protection
- Analytics
- Whitelist

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-dns-guard
```

## Configuration

Configuration file: `/etc/secubox/dns-guard.toml`

## API Endpoints

- `GET /api/v1/dns-guard/status` - Module status
- `GET /api/v1/dns-guard/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
