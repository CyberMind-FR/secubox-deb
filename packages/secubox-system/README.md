# ⚙️ System Hub

System configuration and management

**Category:** System

## Screenshot

![System Hub](../../docs/screenshots/vm/system.png)

## Features

- Settings
- Logs
- Services
- Updates

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-system
```

## Configuration

Configuration file: `/etc/secubox/system.toml`

## API Endpoints

- `GET /api/v1/system/status` - Module status
- `GET /api/v1/system/health` - Health check

## License

MIT License - CyberMind © 2024-2026
