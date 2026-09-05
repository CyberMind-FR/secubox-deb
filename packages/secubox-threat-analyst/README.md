<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 🔬 Threat Analyst

AI-powered threat analysis

**Category:** Security

## Screenshot

![Threat Analyst](../../docs/screenshots/vm/threat-analyst.png)

## Features

- ML detection
- Behavioral analysis
- IOC extraction
- Reports

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-threat-analyst
```

## Configuration

Configuration file: `/etc/secubox/threat-analyst.toml`

## API Endpoints

- `GET /api/v1/threat-analyst/status` - Module status
- `GET /api/v1/threat-analyst/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
