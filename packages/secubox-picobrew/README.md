# 🍺 PicoBrew

Homebrew / fermentation controller

**Category:** IoT

## Screenshot

![PicoBrew](../../docs/screenshots/vm/picobrew.png)

## Features

- Temperature control
- Recipes
- Fermentation log
- Sensors

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-picobrew
```

## Configuration

Configuration file: `/etc/secubox/picobrew.toml`

## API Endpoints

- `GET /api/v1/picobrew/status` - Module status
- `GET /api/v1/picobrew/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
