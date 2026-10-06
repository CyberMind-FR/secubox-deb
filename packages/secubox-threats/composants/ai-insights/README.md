<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# 💡 AI Insights

AI-powered security insights

**Category:** AI

## Screenshot

![AI Insights](../../docs/screenshots/vm/ai-insights.png)

## Features

- Anomaly detection
- Recommendations
- Predictions
- Reports

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-ai-insights
```

## Configuration

Configuration file: `/etc/secubox/ai-insights.toml`

## API Endpoints

- `GET /api/v1/ai-insights/status` - Module status
- `GET /api/v1/ai-insights/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
