# 📦 RezApp

Application deployment and management

**Category:** Services

## Screenshot

![RezApp](../../docs/screenshots/vm/rezapp.png)

## Features

- App deploy
- Lifecycle
- Config
- Status

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-rezapp
```

## Configuration

Configuration file: `/etc/secubox/rezapp.toml`

## API Endpoints

- `GET /api/v1/rezapp/status` - Module status
- `GET /api/v1/rezapp/health` - Health check

## License

LicenseRef-CMSD-1.0 (Source-Disclosed License) — CyberMind © 2024-2026.
See [LICENCE-CMSD-1.0.md](../../LICENCE-CMSD-1.0.md).
