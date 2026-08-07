# 🧪 Metalogizer

Log processor and analyzer

**Category:** Monitoring

## Screenshot

![Metalogizer](../../docs/screenshots/vm/metalogizer.png)

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
sudo apt install secubox-metalogizer
```

## Configuration

Configuration file: `/etc/secubox/metalogizer.toml`

## API Endpoints

- `GET /api/v1/metalogizer/status` - Module status
- `GET /api/v1/metalogizer/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
