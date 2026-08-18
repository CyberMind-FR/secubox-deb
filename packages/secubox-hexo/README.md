<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# ✏️ Hexo Blog

Static blog generator

**Category:** Publishing

## Screenshot

![Hexo Blog](../../docs/screenshots/vm/hexo.png)

## Features

- Markdown
- Themes
- Plugins
- Deploy

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-hexo
```

## Configuration

Configuration file: `/etc/secubox/hexo.toml`

## API Endpoints

- `GET /api/v1/hexo/status` - Module status
- `GET /api/v1/hexo/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
