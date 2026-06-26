# 🗄️ Metoblizer

Centralized log aggregator

**Category:** Monitoring

## Screenshot

![Metoblizer](../../docs/screenshots/vm/metoblizer.png)

## Features

- Log collection
- Central store
- Search
- Retention

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-metoblizer
```

## Configuration

Configuration file: `/etc/secubox/metoblizer.toml`

## API Endpoints

- `GET /api/v1/metoblizer/status` - Module status
- `GET /api/v1/metoblizer/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
