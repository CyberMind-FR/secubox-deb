<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🔌 MCP Server

Model Context Protocol server

**Category:** AI

## Screenshot

![MCP Server](../../docs/screenshots/vm/mcp-server.png)

## Features

- Tool integration
- Context management
- Multi-model
- API

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-mcp-server
```

## Configuration

Configuration file: `/etc/secubox/mcp-server.toml`

## API Endpoints

- `GET /api/v1/mcp-server/status` - Module status
- `GET /api/v1/mcp-server/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
