<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🎨 Streamlit

Streamlit app platform

**Category:** Apps

## Screenshot

![Streamlit](../../docs/screenshots/vm/streamlit.png)

## Features

- App hosting
- Deployment
- Management
- Logs

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-streamlit
```

## Configuration

Configuration file: `/etc/secubox/streamlit.toml`

## API Endpoints

- `GET /api/v1/streamlit/status` - Module status
- `GET /api/v1/streamlit/health` - Health check

## License

MIT License - CyberMind © 2024-2026
