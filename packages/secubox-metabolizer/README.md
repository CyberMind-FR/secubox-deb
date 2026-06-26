# 🧪 Metabolizer

Log processor and analyzer

**Category:** Monitoring

## Screenshot

![Metabolizer](../../docs/screenshots/vm/metabolizer.png)

## Features

- Log parsing
- Pattern analysis
- Pipelines
- Enrichment

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-metabolizer
```

## Configuration

Configuration file: `/etc/secubox/metabolizer.toml`

## API Endpoints

- `GET /api/v1/metabolizer/status` - Module status
- `GET /api/v1/metabolizer/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
