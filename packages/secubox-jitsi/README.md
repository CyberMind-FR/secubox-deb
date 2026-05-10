# 📹 Jitsi Meet

Video conferencing

**Category:** Communication

## Screenshot

![Jitsi Meet](../../docs/screenshots/vm/jitsi.png)

## Features

- Video calls
- Screen share
- Recording
- Lobby

## Installation

```bash
# Add SecuBox repository
curl -fsSL https://apt.secubox.in/install.sh | sudo bash

# Install package
sudo apt install secubox-jitsi
```

## Configuration

Configuration file: `/etc/secubox/jitsi.toml`

## API Endpoints

- `GET /api/v1/jitsi/status` - Module status
- `GET /api/v1/jitsi/health` - Health check

## License

MIT License - CyberMind © 2024-2026
