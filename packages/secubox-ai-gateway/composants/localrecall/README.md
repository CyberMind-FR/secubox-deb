<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🧠 LocalRecall

Local RAG memory system

**Category:** AI

## Screenshot

![LocalRecall](../../docs/screenshots/vm/localrecall.png)

## Features

- Vector storage
- Semantic search
- Document indexing
- API

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-localrecall
```

## Configuration

Configuration file: `/etc/secubox/localrecall.toml`

## API Endpoints

- `GET /api/v1/localrecall/status` - Module status
- `GET /api/v1/localrecall/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
