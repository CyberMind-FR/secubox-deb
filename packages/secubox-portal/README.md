# 🔐 Login Portal

Authentication portal with JWT

**Category:** Access

## Screenshot

![Login Portal](../../docs/screenshots/vm/portal.png)

## Features

- JWT auth
- Sessions
- Password recovery

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-portal
```

## Configuration

Configuration file: `/etc/secubox/portal.toml`

## API Endpoints

- `GET /api/v1/portal/status` - Module status
- `GET /api/v1/portal/health` - Health check

## License

MIT License - CyberMind © 2024-2026
