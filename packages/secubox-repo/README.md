<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 📦 APT Repository

APT repository management

**Category:** Apps

## Screenshot

![APT Repository](../../docs/screenshots/vm/repo.png)

## Features

- Package management
- GPG signing
- Multi-distro
- Uploads

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-repo
```

## Configuration

Configuration file: `/etc/secubox/repo.toml`

## API Endpoints

- `GET /api/v1/repo/status` - Module status
- `GET /api/v1/repo/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
