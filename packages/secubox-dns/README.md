<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🌍 DNS Server

BIND DNS zone management

**Category:** DNS

## Screenshot

![DNS Server](../../docs/screenshots/vm/dns.png)

## Features

- Zone management
- Records
- DNSSEC
- Reverse DNS

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-dns
```

## Configuration

Configuration file: `/etc/secubox/dns.toml`

## API Endpoints

- `GET /api/v1/dns/status` - Module status
- `GET /api/v1/dns/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
