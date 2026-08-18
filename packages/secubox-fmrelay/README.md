<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 📻 FM Relay

rtl_fm to Icecast MP3 mount with live RDS metadata

**Category:** Media

## Screenshot

![FM Relay](../../docs/screenshots/vm/fmrelay.png)

## Features

- SDR FM capture
- Icecast stream
- RDS metadata
- Station presets

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-fmrelay
```

## Configuration

Configuration file: `/etc/secubox/fmrelay.toml`

## API Endpoints

- `GET /api/v1/fmrelay/status` - Module status
- `GET /api/v1/fmrelay/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
