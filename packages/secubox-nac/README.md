# 🛡️ Network Access Control

Client guardian and NAC

**Category:** Security

## Screenshot

![Network Access Control](../../docs/screenshots/vm/nac.png)

## Features

- Device control
- MAC filtering
- Quarantine

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-nac
```

## Configuration

Configuration file: `/etc/secubox/nac.toml`

## API Endpoints

- `GET /api/v1/nac/status` - Module status
- `GET /api/v1/nac/health` - Health check

## License

MIT License - CyberMind © 2024-2026
